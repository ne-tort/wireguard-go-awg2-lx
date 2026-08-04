/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — central deterministic byte stream for Seal-side appearance.
 * All morph "randomness" derives from epoch seed + counter (T-EPOCH).
 * Not a secrecy boundary; replaces scattered math/rand / crypto/rand on hot path.
 */

package device

import "encoding/binary"

// pathologyStreamFill writes dst from seed∥salt∥ctr (xorshift). Same inputs → same bytes.
func pathologyStreamFill(dst, seed []byte, salt byte, ctr uint64) {
	if len(dst) == 0 {
		return
	}
	var state uint64
	if len(seed) >= 8 {
		state = binary.LittleEndian.Uint64(seed[:8])
	}
	if len(seed) >= 16 {
		state ^= binary.LittleEndian.Uint64(seed[8:16])
	}
	state ^= ctr
	state ^= uint64(salt) << 48
	if state == 0 {
		state = 0x9e3779b97f4a7c15
	}
	for i := 0; i < len(dst); {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		v := state
		for j := 0; j < 8 && i < len(dst); j++ {
			dst[i] = byte(v)
			v >>= 8
			i++
		}
	}
}

func pathologyStreamByte(seed []byte, salt byte, ctr uint64) byte {
	var b [1]byte
	pathologyStreamFill(b[:], seed, salt, ctr)
	return b[0]
}
