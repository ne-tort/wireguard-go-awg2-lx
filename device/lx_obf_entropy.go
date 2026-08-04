/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-ENTROPY clear-pad fillers (mieru M3 inspired).
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	lxObfEntropyASCII   = 0
	lxObfEntropyBalance = 1
	lxObfEntropyRandom  = 2
	lxObfBitBalanceTarget = 0.325
)

func strategyByte(name string, keyDerived byte) byte {
	switch name {
	case "ascii":
		return lxObfEntropyASCII
	case "balance":
		return lxObfEntropyBalance
	case "random":
		return lxObfEntropyRandom
	default: // auto
		return keyDerived % 3
	}
}

func fillLxObfPad(dst []byte, ciphertext []byte, strategy byte) {
	if len(dst) == 0 {
		return
	}
	switch strategy % 3 {
	case lxObfEntropyASCII:
		fillASCIIRunPad(dst)
	case lxObfEntropyBalance:
		fillBitBalancePad(dst, ciphertext)
	default:
		_, _ = rand.Read(dst)
	}
}

func fillASCIIRunPad(dst []byte) {
	_, _ = rand.Read(dst)
	run := 24
	if run > len(dst) {
		run = len(dst)
	}
	const printable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+="
	start := 0
	if len(dst) > run {
		var b [2]byte
		_, _ = rand.Read(b[:])
		start = int(binary.LittleEndian.Uint16(b[:])) % (len(dst) - run + 1)
	}
	for i := 0; i < run; i++ {
		dst[start+i] = printable[int(dst[start+i])%len(printable)]
	}
}

func fillBitBalancePad(dst []byte, existing []byte) {
	_, _ = rand.Read(dst)
	zeros := 0
	bits := 0
	for _, c := range existing {
		for i := 0; i < 8; i++ {
			bits++
			if (c>>i)&1 == 0 {
				zeros++
			}
		}
	}
	for i := 0; i < len(dst); i++ {
		for bit := 0; bit < 8; bit++ {
			cur := float64(zeros) / float64(bits+1)
			wantZero := cur > lxObfBitBalanceTarget
			if wantZero {
				dst[i] &^= 1 << bit
				zeros++
			} else {
				dst[i] |= 1 << bit
			}
			bits++
		}
	}
}

// fillLowEntropyInner writes a printable-biased payload used for cover packets
// and optional inner decoy when low_entropy is enabled (mieru M3/M4 lite).
func fillLowEntropyInner(dst []byte) {
	if len(dst) == 0 {
		return
	}
	_, _ = rand.Read(dst)
	const printable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,"
	for i := range dst {
		dst[i] = printable[int(dst[i])%len(printable)]
	}
}
