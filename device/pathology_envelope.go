/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-LEN envelope + cover (T-START/T-IDLE) with cipher tiers.
 *
 * Wire versions (Seal picks one; Open accepts any from the same PSK):
 *   v2 aead:   ver|pad_len|nonce(12)|AEAD(kind|u16|data)|clear_pad     overhead 33
 *   v3 stream: ver|pad_len|nonce(12)|XOR(kind|u16|data)|clear_pad      overhead 17
 *   v4 none:   ver|pad_len|kind|u16|data|clear_pad                     overhead 5
 *
 * Passive DPI cares about length CDF, structural frame, pad entropy — not outer
 * AEAD authenticity. Inner WG already has ChaCha20-Poly1305.
 */

package device

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	pathologyVersionAEAD   = 0x02
	pathologyVersionStream = 0x03
	pathologyVersionNone   = 0x04

	pathologyHdrSize   = 2 // ver + clear_pad_len
	pathologyNonceSize = chacha20poly1305.NonceSize
	pathologyKindSize  = 1
	pathologyLenSize   = 2
	pathologyMetaSize  = pathologyKindSize + pathologyLenSize

	pathologyFixedOverheadAEAD   = pathologyHdrSize + pathologyNonceSize + pathologyMetaSize + chacha20poly1305.Overhead // 33
	pathologyFixedOverheadStream = pathologyHdrSize + pathologyNonceSize + pathologyMetaSize                             // 17
	pathologyFixedOverheadNone   = pathologyHdrSize + pathologyMetaSize                                              // 5
	pathologyMinEnvelope         = pathologyFixedOverheadNone

	// stream XOR covers one AES block (meta + up to 13 B of body).
	// Inner WG is already ChaCha20-Poly1305; full-body outer XOR had no
	// passive-DPI value once length-hide + frame are present.
	pathologyStreamScramble = aes.BlockSize

	pathologyKindWG    = 0
	pathologyKindCover = 1
)

func isPathologyEnvelopeVersion(v byte) bool {
	return v == pathologyVersionAEAD || v == pathologyVersionStream || v == pathologyVersionNone
}

var (
	errPathologyShort   = errors.New("pathology: packet too short")
	errPathologyVersion = errors.New("pathology: unsupported version")
	errPathologyPadLen  = errors.New("pathology: invalid clear pad length")
	errPathologyAuth    = errors.New("pathology: authentication failed")
	errPathologyReplay  = errors.New("pathology: replayed nonce")
	errPathologyWGLen   = errors.New("pathology: invalid inner length")
	errPathologyCover   = errors.New("pathology: cover packet")
	pathologyAAD        = []byte("pathology-v2")
)

var classicWireGuardSizes = map[int]struct{}{
	32: {}, 64: {}, 92: {}, 148: {},
}

func avoidClassicWGSize(base, pad int) int {
	for {
		outer := base + pad
		if _, bad := classicWireGuardSizes[outer]; !bad {
			if pad > 255 {
				for p := 255; p >= 0; p-- {
					if _, bad := classicWireGuardSizes[base+p]; !bad {
						return p
					}
				}
				return 255
			}
			return pad
		}
		pad++
	}
}

// PathologyFixedOverhead is the minimum outer growth for the default (AEAD) cipher.
func PathologyFixedOverhead() int { return pathologyFixedOverheadAEAD }

// PathologyFixedOverheadFor returns fixed envelope overhead for a cipher name.
func PathologyFixedOverheadFor(cipherName string) int {
	switch cipherName {
	case pathologyCipherStream:
		return pathologyFixedOverheadStream
	case pathologyCipherNone:
		return pathologyFixedOverheadNone
	default:
		return pathologyFixedOverheadAEAD
	}
}

type envelopePathology struct {
	aead     cipher.AEAD  // nil unless cipher=aead
	block    cipher.Block // AES-256 for cipher=stream (key schedule cached)
	key      []byte
	cfg      pathologyRuntimeConfig
	cipher   string
	version  byte
	fixedOH  int
	strategy byte
	replay   *pathologyReplayCache
	frameKey []byte
	dcid     []byte
	nonceCtr atomic.Uint64
	noncePre [4]byte // random prefix; counter fills remaining 8 bytes
	epoch    pathologyEpochState
}

func newEnvelopePathology(psk []byte, cfg pathologyRuntimeConfig) (*envelopePathology, error) {
	var err error
	if cfg.Auto {
		applyPathologyAuto(&cfg, psk, false)
	}
	cfg.Mode, err = normalizePathologyMode(cfg.Mode)
	if err != nil {
		return nil, err
	}
	applyPathologyMode(&cfg)
	cfg.Dialog, err = normalizePathologyDialog(cfg.Dialog)
	if err != nil {
		return nil, err
	}
	cfg.Intensity, err = normalizePathologyIntensity(cfg.Intensity)
	if err != nil {
		return nil, err
	}
	cfg.Strategy, err = normalizePathologyStrategy(cfg.Strategy)
	if err != nil {
		return nil, err
	}
	persona, err := normalizePathologyPersona(cfg.Persona)
	if err != nil {
		return nil, err
	}
	cfg.Persona = persona
	if cfg.IdlePersona != "" {
		idle, err := normalizePathologyPersona(cfg.IdlePersona)
		if err != nil {
			return nil, fmt.Errorf("idle_persona: %w", err)
		}
		cfg.IdlePersona = idle
	}
	cfg.Preset, err = normalizePathologyPreset(cfg.Preset)
	if err != nil {
		return nil, err
	}
	applyPathologyPreset(&cfg)
	cfg.Cipher, err = normalizePathologyCipher(cfg.Cipher)
	if err != nil {
		return nil, err
	}
	cfg.Frame, err = normalizePathologyFrame(cfg.Frame)
	if err != nil {
		return nil, err
	}
	cfg.StartDecoy, err = normalizePathologyStartDecoy(cfg.StartDecoy)
	if err != nil {
		return nil, err
	}
	if cfg.RotateSec < 0 {
		return nil, fmt.Errorf("pathology rotate_sec negative")
	}
	if cfg.FrameDCIDLen < 0 || cfg.FrameDCIDLen > 20 {
		return nil, fmt.Errorf("pathology frame_dcid_len must be 0..20")
	}
	if cfg.PadBudget < 0 {
		return nil, fmt.Errorf("pathology pad_budget negative")
	}
	if cfg.PadBudget > 255 {
		cfg.PadBudget = 255
	}
	if cfg.StartCover < 0 || cfg.StartCover > 32 {
		return nil, fmt.Errorf("pathology start_cover must be 0..32")
	}
	if cfg.CoverEveryMs < 0 {
		return nil, fmt.Errorf("pathology cover_interval_ms negative")
	}
	if len(cfg.PadProfile) > 0 {
		cfg.Persona = "custom"
	}
	key, err := derivePathologyKey(psk)
	if err != nil {
		return nil, err
	}
	e := &envelopePathology{
		key:      key,
		cfg:      cfg,
		cipher:   cfg.Cipher,
		strategy: pathologyEntropyRandom, // overwritten by T-EPOCH
		replay:   newPathologyReplayCache(),
		frameKey: append([]byte(nil), key...),
	}
	// Always arm all Open ciphers from one PSK (Seal still uses cfg.Cipher).
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	e.aead = aead
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	e.block = block
	switch cfg.Cipher {
	case pathologyCipherStream:
		e.version = pathologyVersionStream
		e.fixedOH = pathologyFixedOverheadStream
	case pathologyCipherNone:
		e.version = pathologyVersionNone
		e.fixedOH = pathologyFixedOverheadNone
	default:
		e.version = pathologyVersionAEAD
		e.fixedOH = pathologyFixedOverheadAEAD
	}
	if _, err := rand.Read(e.noncePre[:]); err != nil {
		return nil, err
	}
	e.initEpochState(psk)
	return e, nil
}

func (e *envelopePathology) nextNonce(dst []byte) {
	n := e.nonceCtr.Add(1)
	copy(dst[:4], e.noncePre[:])
	binary.BigEndian.PutUint64(dst[4:12], n)
}

func (e *envelopePathology) sealFrame() string {
	t := e.ensureEpoch()
	if t.frame != "" {
		return t.frame
	}
	if e.cfg.Frame == pathologyFrameAuto || e.cfg.Frame == "" {
		return pathologyFrameTLS13
	}
	return e.cfg.Frame
}

func (e *envelopePathology) sealBlob(kind byte, data []byte, idle bool) ([]byte, error) {
	if len(data) > 0xffff {
		return nil, fmt.Errorf("pathology: payload too large")
	}
	t := e.ensureEpoch()
	padLen := e.samplePad(idle, len(data))
	frame := t.frame
	if frame == "" {
		if e.cfg.Frame == pathologyFrameAuto || e.cfg.Frame == "" {
			frame = pathologyFrameTLS13
		} else {
			frame = e.cfg.Frame
		}
	}
	frameOH := pathologyFrameOverhead(frame, e.frameDCIDLen())
	base := e.fixedOH + len(data) + frameOH
	padLen = avoidClassicWGSize(base, padLen)

	envLen := e.fixedOH + len(data) + padLen
	out := make([]byte, frameOH+envLen)
	env := out[frameOH:]

	env[0] = e.version
	env[1] = byte(padLen)

	metaAndData := pathologyMetaSize + len(data)
	var body []byte // region after header (+nonce) holding meta|data [|tag]
	switch e.cipher {
	case pathologyCipherNone:
		body = env[pathologyHdrSize : pathologyHdrSize+metaAndData]
		body[0] = kind
		binary.BigEndian.PutUint16(body[1:3], uint16(len(data)))
		if kind == pathologyKindCover {
			e.fillCoverBody(body[3:], t)
		} else {
			copy(body[3:], data)
		}
	case pathologyCipherStream:
		nonce := env[pathologyHdrSize : pathologyHdrSize+pathologyNonceSize]
		e.nextNonce(nonce)
		body = env[pathologyHdrSize+pathologyNonceSize : pathologyHdrSize+pathologyNonceSize+metaAndData]
		body[0] = kind
		binary.BigEndian.PutUint16(body[1:3], uint16(len(data)))
		if kind == pathologyKindCover {
			e.fillCoverBody(body[3:], t)
		} else {
			copy(body[3:], data)
		}
		e.xorStreamPrefix(nonce, body)
	default: // aead
		nonce := env[pathologyHdrSize : pathologyHdrSize+pathologyNonceSize]
		e.nextNonce(nonce)
		ctStart := pathologyHdrSize + pathologyNonceSize
		pt := env[ctStart : ctStart+metaAndData]
		pt[0] = kind
		binary.BigEndian.PutUint16(pt[1:3], uint16(len(data)))
		if kind == pathologyKindCover {
			e.fillCoverBody(pt[3:], t)
		} else {
			copy(pt[3:], data)
		}
		ct := e.aead.Seal(env[ctStart:ctStart], nonce, pt, pathologyAAD)
		if len(ct) != metaAndData+e.aead.Overhead() {
			return nil, fmt.Errorf("pathology: unexpected seal size")
		}
		body = ct
	}

	pad := env[len(env)-padLen:]
	st := t.strategy
	if e.cfg.LowEntropy {
		st = pathologyEntropyASCII
	}
	ctr := e.nonceCtr.Load()
	fillPathologyPadFromSeed(pad, t.seed, ctr, st)

	if frameOH == 0 {
		return out, nil
	}
	if err := e.frameWrapInto(out[:frameOH], env, frame, t.seed, ctr); err != nil {
		return nil, err
	}
	return out, nil
}

func (e *envelopePathology) fillCoverBody(dst []byte, t *pathologyEpochTable) {
	if len(dst) == 0 {
		return
	}
	if t != nil && len(t.coverBody) > 0 {
		n := copy(dst, t.coverBody)
		for n < len(dst) {
			copied := copy(dst[n:], t.coverBody)
			if copied == 0 {
				break
			}
			n += copied
		}
		return
	}
	fillLowEntropyFromSeed(dst, e.key)
}

// xorStreamPrefix scrambles only meta (+16 B of payload) with one AES block.
// Avoids NewCTR alloc and full-datagram XOR; WG body stays as-is (already AEAD).
func (e *envelopePathology) xorStreamPrefix(nonce, dst []byte) {
	if e.block == nil || len(nonce) != pathologyNonceSize || len(dst) == 0 {
		return
	}
	var iv [aes.BlockSize]byte
	copy(iv[:], nonce)
	var ks [aes.BlockSize]byte
	e.block.Encrypt(ks[:], iv[:])
	n := pathologyStreamScramble
	if n > len(dst) {
		n = len(dst)
	}
	if n > aes.BlockSize {
		n = aes.BlockSize
	}
	for i := 0; i < n; i++ {
		dst[i] ^= ks[i]
	}
}

func (e *envelopePathology) Seal(wg []byte) ([]byte, error) {
	idle := len(wg) == MessageKeepaliveSize
	return e.sealBlob(pathologyKindWG, wg, idle)
}

func (e *envelopePathology) SealCover() ([]byte, error) {
	t := e.ensureEpoch()
	bodyPad := pickPathologyPadQuanta(t.idlePads, e.nonceCtr.Load(), 0)
	n := 24 + bodyPad
	if n > pathologyCoverBodyMax {
		n = pathologyCoverBodyMax
	}
	data := make([]byte, n)
	return e.sealBlob(pathologyKindCover, data, true)
}

func (e *envelopePathology) StartCoverCount() int {
	t := e.ensureEpoch()
	return t.startCover
}

func (e *envelopePathology) StartGap() (min, max time.Duration) {
	return time.Duration(e.cfg.StartGapMin) * time.Millisecond,
		time.Duration(e.cfg.StartGapMax) * time.Millisecond
}

func (e *envelopePathology) CoverEvery() time.Duration {
	if e.cfg.CoverEveryMs <= 0 {
		return 0
	}
	return time.Duration(e.cfg.CoverEveryMs) * time.Millisecond
}

func (e *envelopePathology) StartDecoyMode() string {
	t := e.ensureEpoch()
	return t.startDecoy
}

func (e *envelopePathology) BuildQUICInitialDecoy() ([]byte, error) {
	t := e.ensureEpoch()
	return buildPathologyQUICInitialDecoy(t.seed)
}

func pathologyFixedOHForVersion(ver byte) int {
	switch ver {
	case pathologyVersionStream:
		return pathologyFixedOverheadStream
	case pathologyVersionNone:
		return pathologyFixedOverheadNone
	case pathologyVersionAEAD:
		return pathologyFixedOverheadAEAD
	default:
		return 0
	}
}

func (e *envelopePathology) Open(packet []byte) ([]byte, error) {
	if isPathologyDialogResponse(packet) {
		return nil, errPathologyCover // peer legend reply — not WG
	}
	inner, err := e.frameUnwrap(packet)
	if err != nil {
		if isPathologyLikelyQUICInitial(packet) || isPathologyDialogRequest(packet) {
			return nil, errPathologyCover
		}
		return nil, err
	}
	packet = inner
	if len(packet) < pathologyMinEnvelope {
		return nil, errPathologyShort
	}
	ver := packet[0]
	fixedOH := pathologyFixedOHForVersion(ver)
	if fixedOH == 0 {
		if isPathologyLikelyQUICInitial(packet) {
			return nil, errPathologyCover
		}
		return nil, errPathologyVersion
	}
	if len(packet) < fixedOH {
		return nil, errPathologyShort
	}
	padLen := int(packet[1])
	if padLen > 255 || len(packet) < fixedOH+padLen {
		return nil, errPathologyPadLen
	}
	body := packet[:len(packet)-padLen]

	var plaintext []byte
	switch ver {
	case pathologyVersionNone:
		plaintext = body[pathologyHdrSize:]
	case pathologyVersionStream:
		nonce := body[pathologyHdrSize : pathologyHdrSize+pathologyNonceSize]
		ct := body[pathologyHdrSize+pathologyNonceSize:]
		if len(ct) < pathologyMetaSize {
			return nil, errPathologyShort
		}
		if !e.replay.checkAndAdd(nonce) {
			return nil, errPathologyReplay
		}
		var prefix [aes.BlockSize]byte
		n := pathologyStreamScramble
		if n > len(ct) {
			n = len(ct)
		}
		if n > aes.BlockSize {
			n = aes.BlockSize
		}
		copy(prefix[:], ct[:n])
		e.xorStreamPrefix(nonce, prefix[:n])
		if n < pathologyMetaSize {
			return nil, errPathologyShort
		}
		kind := prefix[0]
		dataLen := int(binary.BigEndian.Uint16(prefix[1:3]))
		if pathologyMetaSize+dataLen != len(ct) {
			return nil, errPathologyWGLen
		}
		if kind == pathologyKindCover {
			return nil, errPathologyCover
		}
		if kind != pathologyKindWG {
			return nil, errPathologyWGLen
		}
		out := make([]byte, dataLen)
		head := n - pathologyMetaSize
		if head > dataLen {
			head = dataLen
		}
		copy(out, prefix[pathologyMetaSize:pathologyMetaSize+head])
		if head < dataLen {
			copy(out[head:], ct[n:n+(dataLen-head)])
		}
		return out, nil
	default: // aead
		nonce := body[pathologyHdrSize : pathologyHdrSize+pathologyNonceSize]
		ct := body[pathologyHdrSize+pathologyNonceSize:]
		if e.aead == nil || len(ct) < e.aead.Overhead()+pathologyMetaSize {
			return nil, errPathologyShort
		}
		if !e.replay.checkAndAdd(nonce) {
			return nil, errPathologyReplay
		}
		plaintext, err = e.aead.Open(nil, nonce, ct, pathologyAAD)
		if err != nil {
			return nil, errPathologyAuth
		}
	}

	if len(plaintext) < pathologyMetaSize {
		return nil, errPathologyWGLen
	}
	kind := plaintext[0]
	dataLen := int(binary.BigEndian.Uint16(plaintext[1:3]))
	if pathologyMetaSize+dataLen != len(plaintext) {
		return nil, errPathologyWGLen
	}
	if kind == pathologyKindCover {
		return nil, errPathologyCover
	}
	if kind != pathologyKindWG {
		return nil, errPathologyWGLen
	}
	return plaintext[3 : 3+dataLen], nil
}

func newPathologyMorpherFromConfig(key []byte, cfg pathologyRuntimeConfig) (PathologyMorpher, error) {
	if len(key) == 0 {
		return newIdentityPathology(), nil
	}
	return newEnvelopePathology(key, cfg)
}
