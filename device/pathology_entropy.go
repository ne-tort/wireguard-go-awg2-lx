/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-ENTROPY clear-pad fillers (seed-driven; no per-packet PRNG).
 */

package device

const (
	pathologyEntropyASCII  = 0
	pathologyEntropyRandom = 1
)

func fillPathologyPadFromSeed(dst, seed []byte, ctr uint64, strategy byte) {
	if len(dst) == 0 {
		return
	}
	pathologyStreamFill(dst, seed, 0xB1, ctr) // salt tag for pad
	if strategy == pathologyEntropyASCII {
		paintASCIIRun(dst, seed, ctr)
	}
}

func paintASCIIRun(dst, seed []byte, ctr uint64) {
	run := 24
	if run > len(dst) {
		run = len(dst)
	}
	const printable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+="
	start := 0
	if len(dst) > run {
		start = int(pathologyStreamByte(seed, 0xA5, ctr)) % (len(dst) - run + 1)
	}
	for i := 0; i < run; i++ {
		dst[start+i] = printable[int(dst[start+i])%len(printable)]
	}
}
