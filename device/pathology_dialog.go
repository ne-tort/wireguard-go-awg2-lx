/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-DIALOG polite start scripts (req→resp), not a real stack.
 *
 * Goal: lazy/first-N DPI sees a matched legend exchange before framed WG.
 * Fields (DNS ID, QNAME, STUN TXID) come from epoch seed — not static CPS.
 */

package device

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	pathologyDialogOff  = "off"
	pathologyDialogAuto = "auto"
	pathologyDialogDNS  = "dns"
	pathologyDialogSTUN = "stun"

	pathologyDialogMinSize       = 20
	pathologyDialogDefaultWaitMs = 80
)

// pathologyDialogStep is one outbound datagram in a start script.
type pathologyDialogStep struct {
	Packet []byte
	WaitMs int // RTT-scale pause after send before next step / initiation
}

func normalizePathologyDialog(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" {
		return pathologyDialogAuto, nil
	}
	switch n {
	case "off", "none", "disabled":
		return pathologyDialogOff, nil
	case "auto", "default":
		return pathologyDialogAuto, nil
	case "dns":
		return pathologyDialogDNS, nil
	case "stun":
		return pathologyDialogSTUN, nil
	default:
		// quic/tls removed: not real req→resp (use start_decoy / start_cover).
		return "", fmt.Errorf("unknown pathology dialog %q (want auto|off|dns|stun)", s)
	}
}

func resolvePathologyDialog(cfg pathologyRuntimeConfig) string {
	d := cfg.Dialog
	if d == "" || d == pathologyDialogAuto {
		if cfg.Intensity <= 1 {
			return pathologyDialogOff
		}
		switch cfg.Mode {
		case "dns":
			return pathologyDialogDNS
		case "stun", "webrtc":
			return pathologyDialogSTUN
		default:
			// quic/tls/balanced/empty — STUN at intensity≥3; else off.
			// QUIC Initial is one-way decoy (start_decoy / intensity), not dialog.
			if cfg.Intensity >= 3 {
				return pathologyDialogSTUN
			}
			return pathologyDialogOff
		}
	}
	return d
}

func (e *envelopePathology) BuildStartDialog() []pathologyDialogStep {
	kind := resolvePathologyDialog(e.cfg)
	if kind == pathologyDialogOff {
		return nil
	}
	t := e.ensureEpoch()
	seed := t.seed
	wait := pathologyDialogDefaultWaitMs
	if e.cfg.StartGapMax > 0 {
		wait = e.cfg.StartGapMin
		if e.cfg.StartGapMax > e.cfg.StartGapMin {
			span := e.cfg.StartGapMax - e.cfg.StartGapMin
			wait = e.cfg.StartGapMin + int(seed[8])%(span+1)
		}
	}
	if wait < 40 {
		wait = 40
	}
	if wait > 250 {
		wait = 250
	}

	switch kind {
	case pathologyDialogDNS:
		req := buildPathologyDNSQuery(seed)
		return []pathologyDialogStep{{Packet: req, WaitMs: wait}}
	case pathologyDialogSTUN:
		req := buildPathologySTUNBindingReq(seed)
		return []pathologyDialogStep{{Packet: req, WaitMs: wait}}
	default:
		return nil
	}
}

// MaybeDialogReply synthesizes a legend response for a polite start request.
// Returns (reply, true) when the packet is a known dialog request.
func (e *envelopePathology) MaybeDialogReply(packet []byte) ([]byte, bool) {
	if len(packet) < pathologyDialogMinSize {
		return nil, false
	}
	if reply, ok := replyPathologyDNSQuery(packet); ok {
		return reply, true
	}
	if reply, ok := replyPathologySTUNBinding(packet); ok {
		return reply, true
	}
	return nil, false
}

func isPathologyDialogRequest(packet []byte) bool {
	if looksLikePathologyDNSQuery(packet) {
		return true
	}
	if looksLikePathologySTUNBindingReq(packet) {
		return true
	}
	return false
}

func isPathologyDialogResponse(packet []byte) bool {
	if looksLikePathologyDNSResponse(packet) {
		return true
	}
	if looksLikePathologySTUNBindingSuccess(packet) {
		return true
	}
	return false
}

func buildPathologyDNSQuery(seed []byte) []byte {
	// ID(2) + flags QDCOUNT=1 + QNAME(label) + QTYPE A + QCLASS IN
	label := make([]byte, 8)
	pathologyStreamFill(label, seed, 0xD0, 1)
	for i := range label {
		label[i] = 'a' + label[i]%26
	}
	out := make([]byte, 12+1+len(label)+1+4)
	pathologyStreamFill(out[0:2], seed, 0xD1, 0)
	// Clear QUIC fixed-bit lookalike, then avoid envelope ver @0.
	out[0] &^= 0x40
	if isPathologyEnvelopeVersion(out[0]) {
		out[0] ^= 0x80
	}
	if out[0] == 0x17 && out[1] == 0x03 {
		out[1] ^= 0x01
	}
	out[2] = 0x01 // RD
	out[3] = 0x00
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT
	off := 12
	out[off] = byte(len(label))
	off++
	copy(out[off:], label)
	off += len(label)
	out[off] = 0 // root
	off++
	binary.BigEndian.PutUint16(out[off:off+2], 1) // A
	binary.BigEndian.PutUint16(out[off+2:off+4], 1) // IN
	return out
}

func parsePathologyDNSQuestionEnd(p []byte) (int, bool) {
	if len(p) < 17 {
		return 0, false
	}
	off := 12
	for off < len(p) {
		l := int(p[off])
		if l == 0 {
			off++
			break
		}
		if l > 63 {
			return 0, false
		}
		off += 1 + l
		if off > len(p) {
			return 0, false
		}
	}
	if off+4 > len(p) {
		return 0, false
	}
	return off + 4, true
}

func looksLikePathologyDNSQuery(p []byte) bool {
	if len(p) < 17 || isPathologyEnvelopeVersion(p[0]) {
		return false
	}
	if p[0] == 0x17 && p[1] == 0x03 { // TLS record
		return false
	}
	if p[2]&0x80 != 0 { // QR
		return false
	}
	if binary.BigEndian.Uint16(p[4:6]) != 1 {
		return false
	}
	if binary.BigEndian.Uint16(p[6:8]) != 0 ||
		binary.BigEndian.Uint16(p[8:10]) != 0 ||
		binary.BigEndian.Uint16(p[10:12]) != 0 {
		return false
	}
	// Mid-flow DNS frame places envelope ver at +12 (no QNAME). Dialog queries
	// use a real label length here (we emit 8); never 0x02/0x03/0x04.
	if isPathologyEnvelopeVersion(p[12]) {
		return false
	}
	end, ok := parsePathologyDNSQuestionEnd(p)
	if !ok || end != len(p) {
		return false
	}
	return p[12] > 0 && p[12] <= 63
}

func looksLikePathologyDNSResponse(p []byte) bool {
	if len(p) < 30 || isPathologyEnvelopeVersion(p[0]) {
		return false
	}
	// DNS ID is not a QUIC/TLS header — only reject clear TLS record prefix.
	if p[0] == 0x17 && p[1] == 0x03 {
		return false
	}
	if p[2]&0x80 == 0 {
		return false
	}
	if binary.BigEndian.Uint16(p[4:6]) != 1 {
		return false
	}
	if binary.BigEndian.Uint16(p[6:8]) < 1 {
		return false
	}
	// Our replies use name compression pointer 0xc00c at answer start.
	qEnd, ok := parsePathologyDNSQuestionEnd(p)
	if !ok || qEnd+12 > len(p) {
		return false
	}
	return p[qEnd] == 0xc0 && p[qEnd+1] == 0x0c
}

func replyPathologyDNSQuery(req []byte) ([]byte, bool) {
	if !looksLikePathologyDNSQuery(req) {
		return nil, false
	}
	qEnd, ok := parsePathologyDNSQuestionEnd(req)
	if !ok {
		return nil, false
	}
	resp := make([]byte, qEnd+16)
	copy(resp, req[:qEnd])
	resp[2] = 0x81 // QR+RD
	resp[3] = 0x80 // RA
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT
	off := qEnd
	resp[off] = 0xc0
	resp[off+1] = 0x0c
	binary.BigEndian.PutUint16(resp[off+2:off+4], 1)   // TYPE A
	binary.BigEndian.PutUint16(resp[off+4:off+6], 1)   // CLASS IN
	binary.BigEndian.PutUint32(resp[off+6:off+10], 60) // TTL
	binary.BigEndian.PutUint16(resp[off+10:off+12], 4) // RDLENGTH
	resp[off+12] = 203
	resp[off+13] = req[0]
	resp[off+14] = req[1]
	resp[off+15] = 1
	return resp, true
}

func buildPathologySTUNBindingReq(seed []byte) []byte {
	out := make([]byte, 20)
	binary.BigEndian.PutUint16(out[0:2], 0x0001)
	binary.BigEndian.PutUint16(out[2:4], 0) // no attrs
	out[4], out[5], out[6], out[7] = 0x21, 0x12, 0xa4, 0x42
	pathologyStreamFill(out[8:20], seed, 0xE0, 0)
	return out
}

func buildPathologyQUICShortAckLike(seed, dcid []byte) []byte {
	if len(dcid) == 0 {
		dcid = make([]byte, 8)
		pathologyStreamFill(dcid, seed, 0xDC, 2)
	}
	oh := 1 + len(dcid) + 1
	out := make([]byte, oh+24)
	r := pathologyStreamByte(seed, 0x51, 9)
	out[0] = 0x40 | (r & 0x20) | (r & 0x04)
	copy(out[1:], dcid)
	out[1+len(dcid)] = pathologyStreamByte(seed, 0x52, 9)
	pathologyStreamFill(out[oh:], seed, 0xAC, 3)
	return out
}

func looksLikePathologySTUNBindingReq(p []byte) bool {
	if len(p) != 20 {
		return false // dialog Binding Request is header-only; mid-flow stun frame carries body
	}
	if binary.BigEndian.Uint16(p[0:2]) != 0x0001 {
		return false
	}
	if p[4] != 0x21 || p[5] != 0x12 || p[6] != 0xa4 || p[7] != 0x42 {
		return false
	}
	return binary.BigEndian.Uint16(p[2:4]) == 0
}

func looksLikePathologySTUNBindingSuccess(p []byte) bool {
	if len(p) < 20 {
		return false
	}
	if binary.BigEndian.Uint16(p[0:2]) != 0x0101 {
		return false
	}
	return p[4] == 0x21 && p[5] == 0x12 && p[6] == 0xa4 && p[7] == 0x42
}

func replyPathologySTUNBinding(req []byte) ([]byte, bool) {
	if !looksLikePathologySTUNBindingReq(req) {
		return nil, false
	}
	// Binding Success + XOR-MAPPED-ADDRESS (IPv4 shaped).
	const attrLen = 8
	out := make([]byte, 20+4+attrLen)
	binary.BigEndian.PutUint16(out[0:2], 0x0101)
	binary.BigEndian.PutUint16(out[2:4], 4+attrLen)
	copy(out[4:20], req[4:20]) // magic + TXID
	binary.BigEndian.PutUint16(out[20:22], 0x0020) // XOR-MAPPED-ADDRESS
	binary.BigEndian.PutUint16(out[22:24], attrLen)
	out[24] = 0
	out[25] = 0x01 // IPv4
	// port ⊕ magic
	port := uint16(3478)
	binary.BigEndian.PutUint16(out[26:28], port^0x2112)
	// addr ⊕ magic
	out[28] = 203 ^ 0x21
	out[29] = 0 ^ 0x12
	out[30] = req[8] ^ 0xa4
	out[31] = req[9] ^ 0x42
	return out, true
}
