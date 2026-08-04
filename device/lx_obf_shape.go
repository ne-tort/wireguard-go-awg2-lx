/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-SHAPE persona / custom pad CDF.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
)

// lxObfPadMode is one weighted pad length in a persona mixture.
type lxObfPadMode struct {
	pad    int
	weight int
}

// Built-in personas: sample clear-pad length so outer UDP size ≠ WG size classes.
var lxObfPersonas = map[string][]lxObfPadMode{
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

func normalizeLxObfPersona(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return "balanced", nil
	}
	if n == "custom" {
		return "custom", nil
	}
	if _, ok := lxObfPersonas[n]; !ok {
		return "", fmt.Errorf("unknown lx_obf persona %q (want random|quic-h3|dns-idle|webrtc|tls13|balanced|custom)", name)
	}
	return n, nil
}

func sampleLxObfPadFromModes(modes []lxObfPadMode, budget int) (int, error) {
	if budget <= 0 {
		return 0, nil
	}
	if len(modes) == 0 {
		modes = lxObfPersonas["balanced"]
	}
	total := 0
	eligible := make([]lxObfPadMode, 0, len(modes))
	for _, m := range modes {
		if m.pad <= budget {
			eligible = append(eligible, m)
			total += m.weight
		}
	}
	if total == 0 {
		return budget, nil
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	r := int(binary.LittleEndian.Uint64(b[:]) % uint64(total))
	for _, m := range eligible {
		r -= m.weight
		if r < 0 {
			return m.pad, nil
		}
	}
	return eligible[len(eligible)-1].pad, nil
}

func sampleLxObfPad(persona string, budget int) (int, error) {
	return sampleLxObfPadFromModes(lxObfPersonas[persona], budget)
}

func (e *envelopeLxObf) samplePad(forIdle bool) (int, error) {
	if len(e.cfg.PadProfile) > 0 {
		return sampleLxObfPadFromModes(e.cfg.PadProfile, e.cfg.PadBudget)
	}
	persona := e.cfg.Persona
	if forIdle && e.cfg.IdlePersona != "" {
		persona = e.cfg.IdlePersona
	}
	return sampleLxObfPad(persona, e.cfg.PadBudget)
}
