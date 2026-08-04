/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-SHAPE persona / custom pad CDF + epoch quanta.
 */

package device

import (
	"fmt"
	"strings"
)

// pathologyPadMode is one weighted pad length in a persona mixture.
type pathologyPadMode struct {
	pad    int
	weight int
}

// Built-in personas: sample clear-pad length so outer UDP size ≠ WG size classes.
var pathologyPersonas = map[string][]pathologyPadMode{
	"random": {
		{0, 2}, {8, 2}, {16, 3}, {24, 2}, {32, 3}, {48, 2}, {64, 2}, {96, 1},
	},
	"quic-h3": {
		{0, 1}, {12, 2}, {20, 3}, {28, 4}, {36, 3}, {44, 2}, {60, 2}, {76, 1}, {100, 1},
	},
	"dns-idle": {
		{0, 3}, {4, 4}, {8, 3}, {12, 2}, {16, 2}, {24, 1},
	},
	"webrtc": {
		{16, 2}, {32, 3}, {48, 4}, {64, 3}, {80, 2}, {96, 1}, {112, 1},
	},
	// tls13: clear-pad modes that push outer lengths toward common TLS 1.3
	// application-data record sizes seen on the wire (legit look, not framing).
	"tls13": {
		{5, 2}, {21, 3}, {37, 4}, {53, 3}, {69, 2}, {85, 2}, {101, 1}, {133, 1},
	},
	"balanced": {
		{0, 2}, {8, 2}, {16, 3}, {24, 2}, {32, 3}, {40, 2}, {56, 2}, {72, 1}, {88, 1},
	},
}

func normalizePathologyPersona(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return "balanced", nil
	}
	if n == "custom" {
		return "custom", nil
	}
	if _, ok := pathologyPersonas[n]; !ok {
		return "", fmt.Errorf("unknown pathology persona %q (want random|quic-h3|dns-idle|webrtc|tls13|balanced|custom)", name)
	}
	return n, nil
}

// samplePad picks a session-stable pad quantum from the epoch table (T-EPOCH).
// No per-packet PRNG — looks more like TLS/QUIC record quanta to lazy DPI.
func (e *envelopePathology) samplePad(forIdle bool, dataLen int) int {
	t := e.ensureEpoch()
	pads := t.pads
	if forIdle && len(t.idlePads) > 0 {
		pads = t.idlePads
	}
	pad := pickPathologyPadQuanta(pads, e.nonceCtr.Load(), dataLen)
	if e.cfg.LowEntropy && pad < 16 && t.padBudget >= 16 {
		pad = 16
	}
	return pad
}
