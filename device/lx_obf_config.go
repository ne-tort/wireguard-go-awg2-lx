/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — runtime config for envelope morpher (customization surface).
 */

package device

import (
	"fmt"
	"strconv"
	"strings"
)

// lxObfRuntimeConfig is the Seal-side customization surface (TECHNIQUES L2+).
// Open is intentionally persona/profile-agnostic for client↔server flexibility.
type lxObfRuntimeConfig struct {
	Persona      string
	IdlePersona  string // used when sealing keepalive-sized WG datagrams
	PadBudget    int
	Strategy     string // auto|ascii|balance|random
	PadProfile   []lxObfPadMode
	StartCover   int // decoy envelopes before handshake initiation
	StartGapMin  int // ms
	StartGapMax  int // ms
	CoverEveryMs int // 0=off; extra cover around keepalives / idle
	LowEntropy   bool
}

func defaultLxObfRuntimeConfig() lxObfRuntimeConfig {
	return lxObfRuntimeConfig{
		Persona:     "balanced",
		IdlePersona: "dns-idle",
		PadBudget:   64,
		Strategy:    "auto",
		StartGapMin: 0,
		StartGapMax: 20,
	}
}

func normalizeLxObfStrategy(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" {
		return "auto", nil
	}
	switch n {
	case "auto", "ascii", "balance", "random":
		return n, nil
	default:
		return "", fmt.Errorf("unknown lx_obf pad_strategy %q (want auto|ascii|balance|random)", s)
	}
}

// parseLxObfPadProfile parses "pad:weight,pad:weight,..." (UAPI).
func parseLxObfPadProfile(spec string) ([]lxObfPadMode, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	parts := strings.Split(spec, ",")
	out := make([]lxObfPadMode, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		a, b, ok := strings.Cut(p, ":")
		if !ok {
			return nil, fmt.Errorf("pad_profile entry %q want pad:weight", p)
		}
		pad, err := strconv.Atoi(strings.TrimSpace(a))
		if err != nil || pad < 0 || pad > 255 {
			return nil, fmt.Errorf("pad_profile pad %q invalid", a)
		}
		w, err := strconv.Atoi(strings.TrimSpace(b))
		if err != nil || w <= 0 {
			return nil, fmt.Errorf("pad_profile weight %q invalid", b)
		}
		out = append(out, lxObfPadMode{pad: pad, weight: w})
	}
	return out, nil
}

func formatLxObfPadProfile(modes []lxObfPadMode) string {
	if len(modes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(modes))
	for _, m := range modes {
		parts = append(parts, fmt.Sprintf("%d:%d", m.pad, m.weight))
	}
	return strings.Join(parts, ",")
}

// parseLxObfGapMs parses "N" or "N-M" milliseconds.
func parseLxObfGapMs(spec string) (min, max int, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 20, nil
	}
	if a, b, ok := strings.Cut(spec, "-"); ok {
		min, err = strconv.Atoi(strings.TrimSpace(a))
		if err != nil {
			return 0, 0, err
		}
		max, err = strconv.Atoi(strings.TrimSpace(b))
		if err != nil {
			return 0, 0, err
		}
	} else {
		min, err = strconv.Atoi(spec)
		if err != nil {
			return 0, 0, err
		}
		max = min
	}
	if min < 0 || max < 0 || max > 5000 || min > max {
		return 0, 0, fmt.Errorf("invalid gap_ms %q", spec)
	}
	return min, max, nil
}
