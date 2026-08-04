/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-FRAME L4 structural wrappers (persona-shaped prefix).
 *
 * Mid-flow datagrams: cleartext structural header + envelope ciphertext.
 * Breaks T16 (max-entropy @ offset 0) without claiming a full native stack.
 *
 * Compatibility: Seal uses configured/epoch Frame; Open peels known frames then
 * falls back to raw envelope (so persona may still differ; Frame should match).
 * Header variable fields (PN, DNS ID, STUN TID) come from epoch seed+ctr —
 * no per-packet math/rand on the Seal path.
 */

package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	pathologyFrameNone      = "none"
	pathologyFrameAuto      = "auto"
	pathologyFrameTLS13     = "tls13"
	pathologyFrameQUICShort = "quic-short"
	pathologyFrameDNS       = "dns"
	pathologyFrameSTUN      = "stun"

	pathologyTLSRecordHdr = 5
	pathologyDNSHdrSize   = 12
	pathologySTUNHdrSize  = 20
)

var (
	errPathologyFrame = errors.New("pathology: frame unwrap failed")
)

func normalizePathologyFrame(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" {
		return "", nil // unset — filled by preset / epoch
	}
	switch n {
	case "none", "off", "raw":
		return pathologyFrameNone, nil
	case "auto":
		return pathologyFrameAuto, nil
	case "tls13", "tls", "tls1.3":
		return pathologyFrameTLS13, nil
	case "quic-short", "quic_short", "quic1rtt", "quic":
		return pathologyFrameQUICShort, nil
	case "dns":
		return pathologyFrameDNS, nil
	case "stun":
		return pathologyFrameSTUN, nil
	default:
		return "", fmt.Errorf("unknown pathology frame %q (want none|auto|tls13|quic-short|dns|stun)", s)
	}
}

func normalizePathologyStartDecoy(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" || n == "none" || n == "off" {
		return "none", nil
	}
	switch n {
	case "quic-initial", "quic_initial", "initial":
		return "quic-initial", nil
	default:
		return "", fmt.Errorf("unknown pathology start_decoy %q (want none|quic-initial)", s)
	}
}

func pathologyFrameOverhead(frame string, dcidLen int) int {
	switch frame {
	case pathologyFrameTLS13:
		return pathologyTLSRecordHdr
	case pathologyFrameQUICShort:
		if dcidLen <= 0 {
			dcidLen = 8
		}
		return 1 + dcidLen + 1 // flags + DCID + 1-byte PN
	case pathologyFrameDNS:
		return pathologyDNSHdrSize
	case pathologyFrameSTUN:
		return pathologySTUNHdrSize
	default:
		return 0
	}
}

// frameWrapInto writes the L4 header into hdr (len == frame overhead).
// payload is the already-placed envelope immediately after hdr in the same buffer.
// Variable header bytes derive from seed+ctr (T-EPOCH); no hot-path PRNG.
func (e *envelopePathology) frameWrapInto(hdr, payload []byte, frame string, seed []byte, ctr uint64) error {
	switch frame {
	case pathologyFrameNone, "":
		return nil
	case pathologyFrameTLS13:
		return writeTLS13AppDataHdr(hdr, len(payload))
	case pathologyFrameQUICShort:
		return writeQUICShortHdr(hdr, e.frameDCID(), seed, ctr)
	case pathologyFrameDNS:
		return writeDNSQueryHdr(hdr, seed, ctr)
	case pathologyFrameSTUN:
		return writeSTUNBindingHdr(hdr, len(payload), seed, ctr)
	default:
		return fmt.Errorf("pathology: unsupported frame %q", frame)
	}
}

func (e *envelopePathology) frameUnwrap(packet []byte) ([]byte, error) {
	// Prefer configured frame. On miss, autodetect (asymmetric Seal frames on hub↔peers).
	cfgFrame := e.cfg.Frame
	if cfgFrame == pathologyFrameAuto {
		cfgFrame = "" // force full autodetect
	}
	if unwrapped, ok := tryUnwrapConfigured(packet, cfgFrame, e.frameDCIDLen()); ok {
		return unwrapped, nil
	}
	if body, ok := tryUnwrapTLS13(packet); ok {
		return body, nil
	}
	if body, ok := tryUnwrapQUICShort(packet, e.frameDCIDLen()); ok {
		return body, nil
	}
	if body, ok := tryUnwrapSTUN(packet); ok {
		return body, nil
	}
	if body, ok := tryUnwrapDNS(packet); ok {
		return body, nil
	}
	if len(packet) > 0 && isPathologyEnvelopeVersion(packet[0]) {
		return packet, nil
	}
	return nil, errPathologyFrame
}

func tryUnwrapConfigured(packet []byte, frame string, dcidLen int) ([]byte, bool) {
	switch frame {
	case pathologyFrameTLS13:
		return tryUnwrapTLS13(packet)
	case pathologyFrameQUICShort:
		return tryUnwrapQUICShort(packet, dcidLen)
	case pathologyFrameDNS:
		return tryUnwrapDNS(packet)
	case pathologyFrameSTUN:
		return tryUnwrapSTUN(packet)
	case pathologyFrameNone, pathologyFrameAuto, "":
		if len(packet) > 0 && isPathologyEnvelopeVersion(packet[0]) {
			return packet, true
		}
		return nil, false
	default:
		return nil, false
	}
}

func (e *envelopePathology) frameDCIDLen() int {
	if e.cfg.FrameDCIDLen > 0 {
		return e.cfg.FrameDCIDLen
	}
	return 8
}

func (e *envelopePathology) frameDCID() []byte {
	if len(e.dcid) > 0 {
		return e.dcid
	}
	return e.makeFrameDCID()
}

// makeFrameDCID derives a stable DCID from key material (no crypto/rand).
func (e *envelopePathology) makeFrameDCID() []byte {
	n := e.frameDCIDLen()
	if n > 20 {
		n = 20
	}
	if n < 1 {
		n = 8
	}
	out := make([]byte, n)
	key := e.aeadKeyHint()
	pathologyStreamFill(out, key, 0xD0, 0)
	return out
}

// aeadKeyHint returns up to 32 bytes derived for stable framing IDs.
func (e *envelopePathology) aeadKeyHint() []byte {
	if len(e.frameKey) > 0 {
		return e.frameKey
	}
	return make([]byte, 32)
}

func writeTLS13AppDataHdr(hdr []byte, payloadLen int) error {
	if len(hdr) != pathologyTLSRecordHdr {
		return fmt.Errorf("pathology tls frame: bad hdr len")
	}
	if payloadLen > 0xffff {
		return fmt.Errorf("pathology tls frame: payload too large")
	}
	hdr[0] = 0x17 // application_data
	hdr[1] = 0x03
	hdr[2] = 0x03 // TLS 1.2 record version (TLS 1.3 wire convention)
	binary.BigEndian.PutUint16(hdr[3:5], uint16(payloadLen))
	return nil
}

func tryUnwrapTLS13(packet []byte) ([]byte, bool) {
	if len(packet) < pathologyTLSRecordHdr {
		return nil, false
	}
	if packet[0] != 0x17 || packet[1] != 0x03 || packet[2] != 0x03 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(packet[3:5]))
	if pathologyTLSRecordHdr+n > len(packet) {
		return nil, false
	}
	// Allow trailing junk after record (some stacks pad); require exact or trailer.
	body := packet[pathologyTLSRecordHdr : pathologyTLSRecordHdr+n]
	if len(body) == 0 || !isPathologyEnvelopeVersion(body[0]) {
		return nil, false
	}
	return body, true
}

func writeQUICShortHdr(hdr, dcid, seed []byte, ctr uint64) error {
	if len(dcid) == 0 || len(dcid) > 20 {
		return fmt.Errorf("pathology quic-short: bad dcid len")
	}
	if len(hdr) != 1+len(dcid)+1 {
		return fmt.Errorf("pathology quic-short: bad hdr len")
	}
	// Fixed bit must be 1; spin/key_phase from epoch stream; pn_len = 1.
	r := pathologyStreamByte(seed, 0x51, ctr)
	hdr[0] = byte(0x40) | (r & 0x20) | (r & 0x04)
	copy(hdr[1:], dcid)
	hdr[1+len(dcid)] = pathologyStreamByte(seed, 0x52, ctr) // PN low byte
	return nil
}

func tryUnwrapQUICShort(packet []byte, dcidLen int) ([]byte, bool) {
	if dcidLen <= 0 {
		dcidLen = 8
	}
	if dcidLen > 20 || len(packet) < 1+dcidLen+1+pathologyMinEnvelope {
		return nil, false
	}
	if packet[0]&0x80 != 0 { // long header
		return nil, false
	}
	if packet[0]&0x40 == 0 { // fixed bit
		return nil, false
	}
	body := packet[1+dcidLen+1:]
	if len(body) == 0 || !isPathologyEnvelopeVersion(body[0]) {
		return nil, false
	}
	return body, true
}

func writeDNSQueryHdr(hdr, seed []byte, ctr uint64) error {
	if len(hdr) != pathologyDNSHdrSize {
		return fmt.Errorf("pathology dns frame: bad hdr len")
	}
	pathologyStreamFill(hdr[:2], seed, 0xD1, ctr)
	// ID[0] must not collide with envelope ver (0x02/0x03/0x04): otherwise Open's
	// frameUnwrap falls through to "raw envelope @0" and drops ~3/256 packets.
	if isPathologyEnvelopeVersion(hdr[0]) {
		hdr[0] ^= 0x80
	}
	// Avoid TLS record prefix 0x17 0x03 0x03 (flags follow at [2]).
	if hdr[0] == 0x17 && hdr[1] == 0x03 {
		hdr[1] ^= 0x01
	}
	hdr[2] = 0x01 // RD
	hdr[3] = 0x00
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT=1 (legend; no real QNAME — envelope follows)
	for i := 6; i < pathologyDNSHdrSize; i++ {
		hdr[i] = 0
	}
	return nil
}

func tryUnwrapDNS(packet []byte) ([]byte, bool) {
	if len(packet) < pathologyDNSHdrSize+pathologyMinEnvelope {
		return nil, false
	}
	// QR=0 query; QDCOUNT=1; AN/NS/AR = 0 (header-only legend).
	// Structural checks run before any "ver @0" bailout: a DNS ID may legally
	// equal an envelope version byte; envelope always starts at +12.
	if packet[2]&0x80 != 0 {
		return nil, false
	}
	if binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return nil, false
	}
	if binary.BigEndian.Uint16(packet[6:8]) != 0 ||
		binary.BigEndian.Uint16(packet[8:10]) != 0 ||
		binary.BigEndian.Uint16(packet[10:12]) != 0 {
		return nil, false
	}
	body := packet[pathologyDNSHdrSize:]
	if !isPathologyEnvelopeVersion(body[0]) {
		return nil, false
	}
	return body, true
}

func writeSTUNBindingHdr(hdr []byte, payloadLen int, seed []byte, ctr uint64) error {
	if len(hdr) != pathologySTUNHdrSize {
		return fmt.Errorf("pathology stun frame: bad hdr len")
	}
	binary.BigEndian.PutUint16(hdr[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(hdr[2:4], uint16(payloadLen))
	hdr[4], hdr[5], hdr[6], hdr[7] = 0x21, 0x12, 0xa4, 0x42
	pathologyStreamFill(hdr[8:20], seed, 0xE1, ctr) // transaction ID
	return nil
}

func tryUnwrapSTUN(packet []byte) ([]byte, bool) {
	if len(packet) < pathologySTUNHdrSize+pathologyMinEnvelope {
		return nil, false
	}
	if packet[4] != 0x21 || packet[5] != 0x12 || packet[6] != 0xa4 || packet[7] != 0x42 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(packet[2:4]))
	if pathologySTUNHdrSize+n > len(packet) {
		return nil, false
	}
	body := packet[pathologySTUNHdrSize : pathologySTUNHdrSize+n]
	if len(body) == 0 || !isPathologyEnvelopeVersion(body[0]) {
		return nil, false
	}
	return body, true
}
