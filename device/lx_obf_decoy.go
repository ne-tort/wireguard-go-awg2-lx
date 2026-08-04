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
	// Long header: form bit 1, fixed bit 1, type=Initial (0b00<<4 for v1) → 0xC0..
	var rb [1]byte
	_, _ = rand.Read(rb[:])
	out[0] = 0xc0 | (rb[0] & 0x0f) // pn length bits in low 2; reserved/random in others
	binary.BigEndian.PutUint32(out[1:5], 0x00000001) // Version Negotiation / v1

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

	// Length varint (2-byte form): remaining after this field = PN + payload.
	remain := len(out) - (off + 2)
	if remain < 64 {
		return nil, errLxObfShort
	}
	// 14-bit varint with 01 prefix
	v := uint16(remain)
	out[off] = byte(v>>8) | 0x40
	out[off+1] = byte(v)
	off += 2

	// 1-byte packet number + encrypted-looking payload
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
	ver := binary.BigEndian.Uint32(packet[1:5])
	return ver == 1 || ver == 0x6b3343cf // QUICv2
}
