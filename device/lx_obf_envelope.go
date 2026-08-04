/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-LEN envelope v2 + cover (T-START/T-IDLE).
 *
 * Wire (v2):
 *   ver(1)=0x02 | clear_pad_len(1) | nonce(12) | AEAD(kind|u16be(len)|data) | clear_pad
 *
 * kind: 0 = WG datagram, 1 = cover (drop after Open).
 * Overhead without pad: 1+1+12+1+2+16 = 33 bytes.
 */

package device

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	lxObfVersion       = 0x02
	lxObfHdrSize       = 2 // ver + clear_pad_len
	lxObfNonceSize     = chacha20poly1305.NonceSize
	lxObfKindSize      = 1
	lxObfLenSize       = 2
	lxObfMetaSize      = lxObfKindSize + lxObfLenSize
	lxObfFixedOverhead = lxObfHdrSize + lxObfNonceSize + lxObfMetaSize + chacha20poly1305.Overhead // 33

	lxObfKindWG    = 0
	lxObfKindCover = 1
)

var (
	errLxObfShort   = errors.New("lx_obf: packet too short")
	errLxObfVersion = errors.New("lx_obf: unsupported version")
	errLxObfPadLen  = errors.New("lx_obf: invalid clear pad length")
	errLxObfAuth    = errors.New("lx_obf: authentication failed")
	errLxObfReplay  = errors.New("lx_obf: replayed nonce")
	errLxObfWGLen   = errors.New("lx_obf: invalid inner length")
	errLxObfCover   = errors.New("lx_obf: cover packet")
	lxObfAAD        = []byte("lx-obf-v2")
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

// LxObfFixedOverhead is the minimum outer growth over a plain WG datagram.
func LxObfFixedOverhead() int { return lxObfFixedOverhead }

type envelopeLxObf struct {
	aead     cipher.AEAD
	cfg      lxObfRuntimeConfig
	strategy byte
	replay   *lxObfReplayCache
}

func newEnvelopeLxObf(psk []byte, cfg lxObfRuntimeConfig) (*envelopeLxObf, error) {
	persona, err := normalizeLxObfPersona(cfg.Persona)
	if err != nil {
		return nil, err
	}
	cfg.Persona = persona
	if cfg.IdlePersona != "" {
		idle, err := normalizeLxObfPersona(cfg.IdlePersona)
		if err != nil {
			return nil, fmt.Errorf("idle_persona: %w", err)
		}
		cfg.IdlePersona = idle
	}
	cfg.Strategy, err = normalizeLxObfStrategy(cfg.Strategy)
	if err != nil {
		return nil, err
	}
	if cfg.PadBudget < 0 {
		return nil, fmt.Errorf("lx_obf pad_budget negative")
	}
	if cfg.PadBudget > 255 {
		cfg.PadBudget = 255
	}
	if cfg.StartCover < 0 || cfg.StartCover > 32 {
		return nil, fmt.Errorf("lx_obf start_cover must be 0..32")
	}
	if cfg.CoverEveryMs < 0 {
		return nil, fmt.Errorf("lx_obf cover_interval_ms negative")
	}
	if len(cfg.PadProfile) > 0 {
		cfg.Persona = "custom"
	}
	key, err := deriveLxObfKey(psk)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &envelopeLxObf{
		aead:     aead,
		cfg:      cfg,
		strategy: strategyByte(cfg.Strategy, key[0]),
		replay:   newLxObfReplayCache(),
	}, nil
}

func (e *envelopeLxObf) sealBlob(kind byte, data []byte, idle bool) ([]byte, error) {
	if len(data) > 0xffff {
		return nil, fmt.Errorf("lx_obf: payload too large")
	}
	padLen, err := e.samplePad(idle)
	if err != nil {
		return nil, err
	}
	if e.cfg.LowEntropy && padLen < 16 && e.cfg.PadBudget >= 16 {
		padLen = 16
	}
	base := lxObfFixedOverhead + len(data)
	padLen = avoidClassicWGSize(base, padLen)

	plaintext := make([]byte, lxObfMetaSize+len(data))
	plaintext[0] = kind
	binary.BigEndian.PutUint16(plaintext[1:3], uint16(len(data)))
	copy(plaintext[3:], data)
	if kind == lxObfKindCover || e.cfg.LowEntropy {
		// Cover / low-entropy: bias clear pad; cover body itself is printable-ish.
		if kind == lxObfKindCover {
			fillLowEntropyInner(plaintext[3:])
		}
	}

	out := make([]byte, lxObfHdrSize+lxObfNonceSize+len(plaintext)+e.aead.Overhead()+padLen)
	out[0] = lxObfVersion
	out[1] = byte(padLen)
	nonce := out[lxObfHdrSize : lxObfHdrSize+lxObfNonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ctStart := lxObfHdrSize + lxObfNonceSize
	ct := e.aead.Seal(out[ctStart:ctStart], nonce, plaintext, lxObfAAD)
	if len(ct) != len(plaintext)+e.aead.Overhead() {
		return nil, fmt.Errorf("lx_obf: unexpected seal size")
	}
	pad := out[ctStart+len(ct):]
	st := e.strategy
	if e.cfg.LowEntropy {
		st = lxObfEntropyASCII
	}
	fillLxObfPad(pad, out[ctStart:ctStart+len(ct)], st)
	return out, nil
}

func (e *envelopeLxObf) Seal(wg []byte) ([]byte, error) {
	idle := len(wg) == MessageKeepaliveSize
	return e.sealBlob(lxObfKindWG, wg, idle)
}

func (e *envelopeLxObf) SealCover() ([]byte, error) {
	// Cover payload size sampled from persona so histogram stays consistent.
	bodyPad, err := e.samplePad(true)
	if err != nil {
		return nil, err
	}
	// Keep cover inner body modest; outer pad still shapes total length.
	n := 24 + bodyPad
	if n > 200 {
		n = 200
	}
	data := make([]byte, n)
	return e.sealBlob(lxObfKindCover, data, true)
}

func (e *envelopeLxObf) StartCoverCount() int { return e.cfg.StartCover }

func (e *envelopeLxObf) StartGap() (min, max time.Duration) {
	return time.Duration(e.cfg.StartGapMin) * time.Millisecond,
		time.Duration(e.cfg.StartGapMax) * time.Millisecond
}

func (e *envelopeLxObf) CoverEvery() time.Duration {
	if e.cfg.CoverEveryMs <= 0 {
		return 0
	}
	return time.Duration(e.cfg.CoverEveryMs) * time.Millisecond
}

func (e *envelopeLxObf) Open(packet []byte) ([]byte, error) {
	if len(packet) < lxObfFixedOverhead {
		return nil, errLxObfShort
	}
	if packet[0] != lxObfVersion {
		return nil, errLxObfVersion
	}
	padLen := int(packet[1])
	if padLen > 255 || len(packet) < lxObfFixedOverhead+padLen {
		return nil, errLxObfPadLen
	}
	body := packet[:len(packet)-padLen]
	nonce := body[lxObfHdrSize : lxObfHdrSize+lxObfNonceSize]
	ct := body[lxObfHdrSize+lxObfNonceSize:]
	if len(ct) < e.aead.Overhead()+lxObfMetaSize {
		return nil, errLxObfShort
	}
	if !e.replay.checkAndAdd(nonce) {
		return nil, errLxObfReplay
	}
	plaintext, err := e.aead.Open(nil, nonce, ct, lxObfAAD)
	if err != nil {
		return nil, errLxObfAuth
	}
	if len(plaintext) < lxObfMetaSize {
		return nil, errLxObfWGLen
	}
	kind := plaintext[0]
	dataLen := int(binary.BigEndian.Uint16(plaintext[1:3]))
	if lxObfMetaSize+dataLen != len(plaintext) {
		return nil, errLxObfWGLen
	}
	if kind == lxObfKindCover {
		return nil, errLxObfCover
	}
	if kind != lxObfKindWG {
		return nil, errLxObfWGLen
	}
	out := make([]byte, dataLen)
	copy(out, plaintext[3:])
	return out, nil
}

func newLxObfMorpherFromConfig(key []byte, cfg lxObfRuntimeConfig) (LxObfMorpher, error) {
	if len(key) == 0 {
		return newIdentityLxObf(), nil
	}
	if cfg.PadBudget == 0 && cfg.Persona != "" && len(cfg.PadProfile) == 0 && !cfg.LowEntropy {
		// allow explicit 0
	}
	return newEnvelopeLxObf(key, cfg)
}
