/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-START L4 decoy: structural QUIC Initial (≥1200).
 *
 * Not a full RFC 9001 handshake (unlike AWG masquerade i1). Goal: first-packet
 * classifier sees long-header QUIC v1 Initial size/shape; peer Open drops it.
 * Device evidence (AWG study): Initial ≫ short-header for first-packet DPI.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	lxObfQUICInitialMin = 1200
	lxObfQUICInitialLen = 1250
)

// buildLxObfQUICInitialDecoy returns a ≥1200-byte UDP datagram shaped like a
// QUIC v1 Initial long header. Payload after the header is CSPRNG (looks encrypted).
func buildLxObfQUICInitialDecoy() ([]byte, error) {
	out := make([]byte, lxObfQUICInitialLen)
	// Long header (RFC 9000 §17.2): Header Form=1, Fixed=1, Type=Initial(00),
	// Reserved=00, Packet Number Length = 1 byte → first byte 0xC0.
	out[0] = 0xc0
	binary.BigEndian.PutUint32(out[1:5], 0x00000001)

	dcidLen := 8
	scidLen := 4
	out[5] = byte(dcidLen)
	off := 6
	if _, err := rand.Read(out[off : off+dcidLen]); err != nil {
		return nil, err
	}
	off += dcidLen
	out[off] = byte(scidLen)
	off++
	if _, err := rand.Read(out[off : off+scidLen]); err != nil {
		return nil, err
	}
	off += scidLen

	// Token length = 0 (1-byte varint)
	out[off] = 0
	off++

	remain := len(out) - (off + 2)
	if remain < 64 {
		return nil, errLxObfShort
	}
	v := uint16(remain)
	out[off] = byte(v>>8) | 0x40
	out[off+1] = byte(v)
	off += 2

	if _, err := rand.Read(out[off:]); err != nil {
		return nil, err
	}
	if len(out) < lxObfQUICInitialMin {
		return nil, errLxObfShort
	}
	return out, nil
}

func isLxObfLikelyQUICInitial(packet []byte) bool {
	if len(packet) < lxObfQUICInitialMin {
		return false
	}
	if packet[0]&0x80 == 0 || packet[0]&0x40 == 0 {
		return false
	}
	// Type bits 4-5 must be Initial (00) for v1.
	if (packet[0]>>4)&0x03 != 0 {
		return false
	}
	ver := binary.BigEndian.Uint32(packet[1:5])
	return ver == 1 || ver == 0x6b3343cf // QUICv2
}
