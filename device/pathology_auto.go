/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — auto profile picker (Seal-local; only key must match peers).
 *
 * Production auto picks one curated profile (matrix-proven), not independent
 * knobs. Seed is stable for the hour from PSK (same key → same pick), so
 * restarts do not thrash the morph. reseed=true uses crypto/rand (retry path).
 */

package device

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// pathologyAutoProfile is one Seal-side bundle known-good from hub matrix.
// dns mode is intentionally absent (size/overhead variance); use explicit frame=dns.
type pathologyAutoProfile struct {
	mode      string
	cipher    string
	frame     string
	dialog    string
	intensity int
	rotateSec int
	startDecoy string
}

// Curated catalog: all members scored ≥~0.80 vs plain in hub matrix (P1/P4).
var pathologyAutoCatalog = []pathologyAutoProfile{
	{mode: "tls", cipher: pathologyCipherStream, frame: pathologyFrameTLS13, dialog: pathologyDialogSTUN, intensity: 3, rotateSec: 3600},
	{mode: "quic", cipher: pathologyCipherStream, frame: pathologyFrameAuto, dialog: pathologyDialogSTUN, intensity: 3, rotateSec: 3600, startDecoy: "quic-initial"},
	{mode: "stun", cipher: pathologyCipherStream, frame: pathologyFrameSTUN, dialog: pathologyDialogSTUN, intensity: 2, rotateSec: 3600},
	{mode: "webrtc", cipher: pathologyCipherStream, frame: pathologyFrameQUICShort, dialog: pathologyDialogSTUN, intensity: 3, rotateSec: 1800},
	{mode: "balanced", cipher: pathologyCipherStream, frame: pathologyFrameAuto, dialog: pathologyDialogAuto, intensity: 3, rotateSec: 3600},
	{mode: "tls", cipher: pathologyCipherNone, frame: pathologyFrameTLS13, dialog: pathologyDialogOff, intensity: 2, rotateSec: 0},
	{mode: "tls", cipher: pathologyCipherStream, frame: pathologyFrameTLS13, dialog: pathologyDialogDNS, intensity: 3, rotateSec: 3600},
	{mode: "quic", cipher: pathologyCipherStream, frame: pathologyFrameQUICShort, dialog: pathologyDialogOff, intensity: 2, rotateSec: 1800, startDecoy: "quic-initial"},
}

// applyPathologyAuto fills unset morph knobs from a curated catalog.
// Explicit non-empty / non-zero user fields are preserved after the pick
// (profile fills only empty slots).
func applyPathologyAuto(cfg *pathologyRuntimeConfig, psk []byte, reseed bool) {
	if !cfg.Auto {
		return
	}
	var b [16]byte
	if reseed {
		_, _ = rand.Read(b[:])
	} else {
		h := sha256.New()
		_, _ = h.Write([]byte("pathology-auto-v2"))
		_, _ = h.Write(psk)
		var hour [8]byte
		binary.BigEndian.PutUint64(hour[:], uint64(time.Now().Unix()/3600))
		_, _ = h.Write(hour[:])
		sum := h.Sum(nil)
		copy(b[:], sum[:16])
	}
	idx := int(binary.LittleEndian.Uint64(b[0:8]) % uint64(len(pathologyAutoCatalog)))
	p := pathologyAutoCatalog[idx]

	if cfg.Mode == "" {
		cfg.Mode = p.mode
	}
	if cfg.Intensity == 0 {
		cfg.Intensity = p.intensity
	}
	if cfg.Cipher == "" {
		cfg.Cipher = p.cipher
		if cfg.Preset == "" {
			cfg.Preset = pathologyPresetCustom
		}
	}
	if cfg.Frame == "" {
		cfg.Frame = p.frame
	}
	if cfg.Dialog == "" || cfg.Dialog == pathologyDialogAuto {
		// Keep auto resolution via mode/intensity unless profile pins dns/stun/off.
		if p.dialog != pathologyDialogAuto {
			cfg.Dialog = p.dialog
		}
	}
	if cfg.RotateSec == pathologyDefaultRotateSec {
		cfg.RotateSec = p.rotateSec
	}
	if (cfg.StartDecoy == "" || cfg.StartDecoy == "none") && p.startDecoy != "" {
		cfg.StartDecoy = p.startDecoy
	}
}
