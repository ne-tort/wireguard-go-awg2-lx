/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-FRAME L4 structural wrappers (persona-shaped prefix).
 *
 * Mid-flow datagrams: cleartext structural header + envelope ciphertext.
 * Breaks T16 (max-entropy @ offset 0) without claiming a full native stack.
 *
 * Compatibility: Seal uses configured Frame; Open peels known frames then
 * falls back to raw envelope (so persona may still differ; Frame should match).
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	lxObfFrameNone      = "none"
	lxObfFrameTLS13     = "tls13"
	lxObfFrameQUICShort = "quic-short"
	lxObfFrameDNS       = "dns"
	lxObfFrameSTUN      = "stun"

	lxObfTLSRecordHdr = 5
	lxObfDNSHdrSize   = 12
	lxObfSTUNHdrSize  = 20
)

var (
	errLxObfFrame = errors.New("lx_obf: frame unwrap failed")
)

func normalizeLxObfFrame(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" {
		return lxObfFrameNone, nil
	}
	switch n {
	case "none", "off", "raw":
		return lxObfFrameNone, nil
	case "tls13", "tls", "tls1.3":
		return lxObfFrameTLS13, nil
	case "quic-short", "quic_short", "quic1rtt", "quic":
		return lxObfFrameQUICShort, nil
	case "dns":
		return lxObfFrameDNS, nil
	case "stun":
		return lxObfFrameSTUN, nil
	default:
		return "", fmt.Errorf("unknown lx_obf frame %q (want none|tls13|quic-short|dns|stun)", s)
	}
}

func normalizeLxObfStartDecoy(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" || n == "none" || n == "off" {
		return "none", nil
	}
	switch n {
	case "quic-initial", "quic_initial", "initial":
		return "quic-initial", nil
	default:
		return "", fmt.Errorf("unknown lx_obf start_decoy %q (want none|quic-initial)", s)
	}
}

func lxObfFrameOverhead(frame string, dcidLen int) int {
	switch frame {
	case lxObfFrameTLS13:
		return lxObfTLSRecordHdr
	case lxObfFrameQUICShort:
		if dcidLen <= 0 {
			dcidLen = 8
		}
		return 1 + dcidLen + 1 // flags + DCID + 1-byte PN
	case lxObfFrameDNS:
		return lxObfDNSHdrSize
	case lxObfFrameSTUN:
		return lxObfSTUNHdrSize
	default:
		return 0
	}
}

func (e *envelopeLxObf) frameWrap(envelope []byte) ([]byte, error) {
	switch e.cfg.Frame {
	case lxObfFrameNone, "":
		return envelope, nil
	case lxObfFrameTLS13:
		return wrapTLS13AppData(envelope)
	case lxObfFrameQUICShort:
		return wrapQUICShort(envelope, e.frameDCID())
	case lxObfFrameDNS:
		return wrapDNSQuery(envelope)
	case lxObfFrameSTUN:
		return wrapSTUNBinding(envelope)
	default:
		return nil, fmt.Errorf("lx_obf: unsupported frame %q", e.cfg.Frame)
	}
}

func (e *envelopeLxObf) frameUnwrap(packet []byte) ([]byte, error) {
	// Prefer configured frame, then autodetection of known structural prefixes.
	if unwrapped, ok := tryUnwrapConfigured(packet, e.cfg.Frame, e.frameDCIDLen()); ok {
		return unwrapped, nil
	}
	if e.cfg.Frame != lxObfFrameNone && e.cfg.Frame != "" {
		// Configured frame failed — still try others / raw (compat during rollout).
	}
	if body, ok := tryUnwrapTLS13(packet); ok {
		return body, nil
	}
	if body, ok := tryUnwrapQUICShort(packet, e.frameDCIDLen()); ok {
		return body, nil
	}
	if body, ok := tryUnwrapDNS(packet); ok {
		return body, nil
	}
	if body, ok := tryUnwrapSTUN(packet); ok {
		return body, nil
	}
	// Raw envelope (ver=0x02).
	if len(packet) > 0 && packet[0] == lxObfVersion {
		return packet, nil
	}
	return nil, errLxObfFrame
}

func tryUnwrapConfigured(packet []byte, frame string, dcidLen int) ([]byte, bool) {
	switch frame {
	case lxObfFrameTLS13:
		return tryUnwrapTLS13(packet)
	case lxObfFrameQUICShort:
		return tryUnwrapQUICShort(packet, dcidLen)
	case lxObfFrameDNS:
		return tryUnwrapDNS(packet)
	case lxObfFrameSTUN:
		return tryUnwrapSTUN(packet)
	case lxObfFrameNone, "":
		if len(packet) > 0 && packet[0] == lxObfVersion {
			return packet, true
		}
		return nil, false
	default:
		return nil, false
	}
}

func (e *envelopeLxObf) frameDCIDLen() int {
	if e.cfg.FrameDCIDLen > 0 {
		return e.cfg.FrameDCIDLen
	}
	return 8
}

func (e *envelopeLxObf) frameDCID() []byte {
	n := e.frameDCIDLen()
	if n > 20 {
		n = 20
	}
	if n < 1 {
		n = 8
	}
	// Stable per-session DCID from AEAD key material (first N key bytes via derive salt).
	out := make([]byte, n)
	key := e.aeadKeyHint()
	copy(out, key)
	if n > len(key) {
		_, _ = rand.Read(out[len(key):])
	}
	return out
}

// aeadKeyHint returns up to 32 bytes derived for stable framing IDs.
func (e *envelopeLxObf) aeadKeyHint() []byte {
	// ChaCha20-Poly1305 key is not exported; use a dedicated field if set.
	if len(e.frameKey) > 0 {
		return e.frameKey
	}
	return make([]byte, 32)
}

func wrapTLS13AppData(payload []byte) ([]byte, error) {
	if len(payload) > 0xffff {
		return nil, fmt.Errorf("lx_obf tls frame: payload too large")
	}
	out := make([]byte, lxObfTLSRecordHdr+len(payload))
	out[0] = 0x17 // application_data
	out[1] = 0x03
	out[2] = 0x03 // TLS 1.2 record version (TLS 1.3 wire convention)
	binary.BigEndian.PutUint16(out[3:5], uint16(len(payload)))
	copy(out[5:], payload)
	return out, nil
}

func tryUnwrapTLS13(packet []byte) ([]byte, bool) {
	if len(packet) < lxObfTLSRecordHdr {
		return nil, false
	}
	if packet[0] != 0x17 || packet[1] != 0x03 || packet[2] != 0x03 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(packet[3:5]))
	if lxObfTLSRecordHdr+n > len(packet) {
		return nil, false
	}
	// Allow trailing junk after record (some stacks pad); require exact or trailer.
	body := packet[lxObfTLSRecordHdr : lxObfTLSRecordHdr+n]
	if len(body) == 0 || body[0] != lxObfVersion {
		return nil, false
	}
	return body, true
}

func wrapQUICShort(payload []byte, dcid []byte) ([]byte, error) {
	if len(dcid) == 0 || len(dcid) > 20 {
		return nil, fmt.Errorf("lx_obf quic-short: bad dcid len")
	}
	// Fixed bit must be 1; spin/key_phase randomized lightly; pn_len = 1.
	var spin byte
	_ = spin
	var b [1]byte
	_, _ = rand.Read(b[:])
	first := byte(0x40) | ((b[0] & 0x20)) | (b[0]&0x04) | 0x00 // pn_len-1 = 0 → 1 byte PN
	out := make([]byte, 1+len(dcid)+1+len(payload))
	out[0] = first
	copy(out[1:], dcid)
	out[1+len(dcid)] = b[0] // PN low byte
	copy(out[1+len(dcid)+1:], payload)
	return out, nil
}

func tryUnwrapQUICShort(packet []byte, dcidLen int) ([]byte, bool) {
	if dcidLen <= 0 {
		dcidLen = 8
	}
	if dcidLen > 20 || len(packet) < 1+dcidLen+1+lxObfFixedOverhead {
		return nil, false
	}
	if packet[0]&0x80 != 0 { // long header
		return nil, false
	}
	if packet[0]&0x40 == 0 { // fixed bit
		return nil, false
	}
	body := packet[1+dcidLen+1:]
	if len(body) == 0 || body[0] != lxObfVersion {
		return nil, false
	}
	return body, true
}

func wrapDNSQuery(payload []byte) ([]byte, error) {
	out := make([]byte, lxObfDNSHdrSize+len(payload))
	var id [2]byte
	_, _ = rand.Read(id[:])
	copy(out[0:2], id[:])
	out[2] = 0x01 // RD
	out[3] = 0x00
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT=1 (legend only; body is envelope)
	copy(out[lxObfDNSHdrSize:], payload)
	return out, nil
}

func tryUnwrapDNS(packet []byte) ([]byte, bool) {
	if len(packet) < lxObfDNSHdrSize+lxObfFixedOverhead {
		return nil, false
	}
	// QR=0 query; not a response.
	if packet[2]&0x80 != 0 {
		return nil, false
	}
	body := packet[lxObfDNSHdrSize:]
	if body[0] != lxObfVersion {
		return nil, false
	}
	return body, true
}

func wrapSTUNBinding(payload []byte) ([]byte, error) {
	out := make([]byte, lxObfSTUNHdrSize+len(payload))
	binary.BigEndian.PutUint16(out[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))
	// Magic cookie
	out[4], out[5], out[6], out[7] = 0x21, 0x12, 0xa4, 0x42
	_, _ = rand.Read(out[8:20]) // transaction ID
	copy(out[lxObfSTUNHdrSize:], payload)
	return out, nil
}

func tryUnwrapSTUN(packet []byte) ([]byte, bool) {
	if len(packet) < lxObfSTUNHdrSize+lxObfFixedOverhead {
		return nil, false
	}
	if packet[4] != 0x21 || packet[5] != 0x12 || packet[6] != 0xa4 || packet[7] != 0x42 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(packet[2:4]))
	if lxObfSTUNHdrSize+n > len(packet) {
		return nil, false
	}
	body := packet[lxObfSTUNHdrSize : lxObfSTUNHdrSize+n]
	if len(body) == 0 || body[0] != lxObfVersion {
		return nil, false
	}
	return body, true
}
