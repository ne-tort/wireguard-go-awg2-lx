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

const (
	pathologyCipherAEAD   = "aead"
	pathologyCipherStream = "stream"
	pathologyCipherNone   = "none"

	pathologyPresetSafe     = "safe"
	pathologyPresetBalanced = "balanced"
	pathologyPresetFast     = "fast"
	pathologyPresetCustom   = "custom"

	pathologyDefaultIntensity = 3
	pathologyMinIntensity     = 1
	pathologyMaxIntensity     = 5
)

// pathologyRuntimeConfig is the Seal-side customization surface (TECHNIQUES L2+).
// Open is persona/frame/cipher-agnostic (multi-cipher by wire version).
// Only the shared key must match peers.
type pathologyRuntimeConfig struct {
	Persona      string
	IdlePersona  string // used when sealing keepalive-sized WG datagrams
	PadBudget    int
	Strategy     string // auto|ascii|random  (balance removed)
	PadProfile   []pathologyPadMode
	StartCover   int // decoy envelopes before handshake initiation
	StartGapMin  int // ms
	StartGapMax  int // ms
	CoverEveryMs int // 0=off; extra cover around keepalives / idle
	LowEntropy   bool
	Frame        string // none|auto|tls13|quic-short|dns|stun
	FrameDCIDLen int    // 1..20 for quic-short; 0→8
	StartDecoy   string // none|quic-initial
	Cipher       string // aead|stream|none — Seal choice; Open accepts all
	Preset       string // safe|balanced|fast|custom — fills unset cipher/frame defaults
	RotateSec    int    // T-EPOCH bucket seconds; 0=connection-scoped; default 3600
	Intensity    int    // 1..5 morph aggressiveness (T-EPOCH); 0→3
	Mode         string // UX sugar: quic|tls|dns|stun|webrtc|balanced
	ModePrefer   string // preferred frame when Frame=auto (from mode)
	Dialog       string // auto|off|dns|stun|quic|tls
	Auto         bool   // pick unset morph knobs from catalog
}

func defaultPathologyRuntimeConfig() pathologyRuntimeConfig {
	return pathologyRuntimeConfig{
		// Persona empty → mode may fill; else normalize → balanced.
		IdlePersona: "dns-idle",
		PadBudget:   64,
		Strategy:    "auto",
		StartGapMin: 40,
		StartGapMax: 120,
		StartDecoy:  "none",
		RotateSec:   pathologyDefaultRotateSec,
		Intensity:   0, // normalize → 3; Auto may pick 2..4 first
		Dialog:      pathologyDialogAuto,
	}
}

func normalizePathologyCipher(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" {
		return "", nil // unset — filled by preset
	}
	switch n {
	case "aead", "full", "poly1305", "chacha20-poly1305":
		return pathologyCipherAEAD, nil
	case "stream", "chacha", "chacha20", "xor":
		return pathologyCipherStream, nil
	case "none", "off", "length", "pad", "lite":
		return pathologyCipherNone, nil
	default:
		return "", fmt.Errorf("unknown pathology cipher %q (want aead|stream|none)", s)
	}
}

func normalizePathologyPreset(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" {
		return pathologyPresetBalanced, nil // recommended default under lazy UDP DPI
	}
	switch n {
	case "safe", "max", "paranoid":
		return pathologyPresetSafe, nil
	case "balanced", "default":
		return pathologyPresetBalanced, nil
	case "fast", "perf", "speed":
		return pathologyPresetFast, nil
	case "custom", "none", "off":
		return pathologyPresetCustom, nil
	default:
		return "", fmt.Errorf("unknown pathology preset %q (want safe|balanced|fast|custom)", s)
	}
}

func normalizePathologyIntensity(n int) (int, error) {
	if n == 0 {
		return pathologyDefaultIntensity, nil
	}
	if n < pathologyMinIntensity || n > pathologyMaxIntensity {
		return 0, fmt.Errorf("pathology intensity must be %d..%d", pathologyMinIntensity, pathologyMaxIntensity)
	}
	return n, nil
}

// normalizePathologyMode accepts UX mode aliases (persona+frame sugar).
func normalizePathologyMode(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" {
		return "", nil
	}
	switch n {
	case "quic", "quic-h3", "h3":
		return "quic", nil
	case "tls", "tls13", "tls1.3":
		return "tls", nil
	case "dns":
		return "dns", nil
	case "stun":
		return "stun", nil
	case "webrtc", "rtc":
		return "webrtc", nil
	case "balanced", "default":
		return "balanced", nil
	default:
		return "", fmt.Errorf("unknown pathology mode %q (want quic|tls|dns|stun|webrtc|balanced)", s)
	}
}

// applyPathologyMode fills unset persona/frame from mode shorthand.
func applyPathologyMode(cfg *pathologyRuntimeConfig) {
	switch cfg.Mode {
	case "quic":
		if cfg.Persona == "" {
			cfg.Persona = "quic-h3"
		}
		if cfg.Frame == "" {
			cfg.Frame = pathologyFrameAuto
		}
		cfg.ModePrefer = pathologyFrameQUICShort
		// QUIC Initial is one-way decoy (not dialog).
		if cfg.StartDecoy == "" || cfg.StartDecoy == "none" {
			cfg.StartDecoy = "quic-initial"
		}
	case "tls":
		if cfg.Persona == "" {
			cfg.Persona = "tls13"
		}
		if cfg.Frame == "" {
			cfg.Frame = pathologyFrameTLS13
		}
		cfg.ModePrefer = pathologyFrameTLS13
	case "dns":
		if cfg.Persona == "" {
			cfg.Persona = "dns-idle"
		}
		if cfg.Frame == "" {
			cfg.Frame = pathologyFrameDNS
		}
		cfg.ModePrefer = pathologyFrameDNS
	case "stun":
		if cfg.Persona == "" {
			cfg.Persona = "webrtc"
		}
		if cfg.Frame == "" {
			cfg.Frame = pathologyFrameSTUN
		}
		cfg.ModePrefer = pathologyFrameSTUN
	case "webrtc":
		if cfg.Persona == "" {
			cfg.Persona = "webrtc"
		}
		if cfg.Frame == "" {
			cfg.Frame = pathologyFrameQUICShort
		}
		cfg.ModePrefer = pathologyFrameQUICShort
	case "balanced":
		if cfg.Persona == "" {
			cfg.Persona = "balanced"
		}
		if cfg.Frame == "" {
			cfg.Frame = pathologyFrameAuto
		}
		cfg.ModePrefer = pathologyFrameTLS13
	}
}

// applyPathologyPreset fills cipher/frame defaults for named performance/security tiers
// without overriding explicit user choices (empty = unset at this stage).
func applyPathologyPreset(cfg *pathologyRuntimeConfig) {
	switch cfg.Preset {
	case pathologyPresetSafe:
		if cfg.Cipher == "" {
			cfg.Cipher = pathologyCipherAEAD
		}
	case pathologyPresetBalanced, pathologyPresetCustom, "":
		if cfg.Cipher == "" {
			cfg.Cipher = pathologyCipherStream
		}
		// Close T16 cheaply: structural prefix without outer AEAD.
		if cfg.Frame == "" {
			cfg.Frame = pathologyFrameTLS13
		}
	case pathologyPresetFast:
		if cfg.Cipher == "" {
			cfg.Cipher = pathologyCipherNone
		}
		if cfg.Frame == "" {
			cfg.Frame = pathologyFrameTLS13
		}
		if cfg.PadBudget == 64 {
			cfg.PadBudget = 24
		}
	}
	if cfg.Cipher == "" {
		cfg.Cipher = pathologyCipherStream
	}
}

func normalizePathologyStrategy(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" {
		return "auto", nil
	}
	switch n {
	case "auto", "ascii", "random":
		return n, nil
	case "balance", "bitbalance", "bit-balance":
		// Removed: expensive & DPI-useless; coerce to random.
		return "random", nil
	default:
		return "", fmt.Errorf("unknown pathology pad_strategy %q (want auto|ascii|random)", s)
	}
}

// pathologyIntensityPolicy is the central morph aggressiveness table (1=cheap … 5=max blur).
type pathologyIntensityPolicy struct {
	padScale   float64  // multiply pad budget inside epoch
	autoFrames []string // Frame=auto allowlist
	decoyDenom int      // auto quic-initial chance 1/N; 0 = never
	coverMax   int      // max auto start_cover when unset
	asciiBias  bool     // auto strategy prefers ascii
}

func pathologyPolicyForIntensity(level int) pathologyIntensityPolicy {
	switch level {
	case 1: // minimal — length+tls frame only
		return pathologyIntensityPolicy{
			padScale: 0.4, autoFrames: []string{pathologyFrameTLS13},
			decoyDenom: 0, coverMax: 0,
		}
	case 2:
		return pathologyIntensityPolicy{
			padScale: 0.7, autoFrames: []string{pathologyFrameTLS13},
			decoyDenom: 16, coverMax: 1,
		}
	case 4:
		return pathologyIntensityPolicy{
			padScale: 1.25, autoFrames: []string{pathologyFrameTLS13, pathologyFrameQUICShort},
			decoyDenom: 4, coverMax: 4, asciiBias: true,
		}
	case 5: // max morph (dns allowed in auto; still no stun — rare + costly)
		return pathologyIntensityPolicy{
			padScale: 1.5, autoFrames: []string{pathologyFrameTLS13, pathologyFrameQUICShort, pathologyFrameDNS},
			decoyDenom: 3, coverMax: 6, asciiBias: true,
		}
	default: // 3 — recommended under lazy UDP DPI
		return pathologyIntensityPolicy{
			padScale: 1.0, autoFrames: []string{pathologyFrameTLS13, pathologyFrameQUICShort},
			decoyDenom: 8, coverMax: 3,
		}
	}
}

// parsePathologyPadProfile parses "pad:weight,pad:weight,..." (UAPI).
func parsePathologyPadProfile(spec string) ([]pathologyPadMode, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	parts := strings.Split(spec, ",")
	out := make([]pathologyPadMode, 0, len(parts))
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
		out = append(out, pathologyPadMode{pad: pad, weight: w})
	}
	return out, nil
}

func formatPathologyPadProfile(modes []pathologyPadMode) string {
	if len(modes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(modes))
	for _, m := range modes {
		parts = append(parts, fmt.Sprintf("%d:%d", m.pad, m.weight))
	}
	return strings.Join(parts, ",")
}

// parsePathologyGapMs parses "N" or "N-M" milliseconds.
func parsePathologyGapMs(spec string) (min, max int, err error) {
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
