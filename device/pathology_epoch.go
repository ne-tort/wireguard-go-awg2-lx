/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-EPOCH session morph table.
 *
 * Seal-side constants are derived once per epoch (wall-clock bucket or
 * connection-scoped when rotate_sec=0), not re-randomized every datagram.
 * All Seal-side "random" appearance (pad, frame headers, decoy, cover) comes
 * from this table's seed + packet counter. Open stays persona/frame-agnostic;
 * cipher never rotates mid-session.
 */

package device

import (
	"sync"
	"time"
)

const (
	pathologyDefaultRotateSec = 3600
	pathologyCoverBodyMax     = 200
)

// pathologyEpochTable is the Seal-side morph snapshot for one epoch.
type pathologyEpochTable struct {
	epoch      uint64
	padBudget  int
	pads       []int // weighted pad quanta (deterministic pick)
	idlePads   []int
	strategy   byte
	frame      string // effective Seal frame (when cfg frame is auto/empty-handled)
	startCover int
	startDecoy string
	coverBody  []byte
	seed       []byte
	dcid       []byte
}

type pathologyEpochState struct {
	mu      sync.Mutex
	psk     []byte
	rotate  int // seconds; 0 = single table for morpher lifetime
	cached  pathologyEpochTable
	have    bool
	connEpo uint64 // fixed epoch when rotate==0
}

func (e *envelopePathology) initEpochState(psk []byte) {
	rot := e.cfg.RotateSec
	if rot < 0 {
		rot = pathologyDefaultRotateSec
	}
	e.epoch = pathologyEpochState{
		psk:    append([]byte(nil), psk...),
		rotate: rot,
	}
	if rot == 0 {
		// Connection-scoped Seal table (sides may differ — Open is agnostic).
		e.epoch.connEpo = uint64(time.Now().UnixNano())
	}
	_ = e.refreshEpochLocked(true)
}

func (e *envelopePathology) currentEpochID() uint64 {
	if e.epoch.rotate <= 0 {
		return e.epoch.connEpo
	}
	return uint64(time.Now().Unix()) / uint64(e.epoch.rotate)
}

// ensureEpoch returns the cached morph table, refreshing on bucket change.
func (e *envelopePathology) ensureEpoch() *pathologyEpochTable {
	id := e.currentEpochID()
	e.epoch.mu.Lock()
	defer e.epoch.mu.Unlock()
	if e.epoch.have && e.epoch.cached.epoch == id {
		return &e.epoch.cached
	}
	_ = e.refreshEpochLocked(false)
	return &e.epoch.cached
}

// refreshEpochLocked builds a new table. Caller holds e.epoch.mu unless boot=true
// and mutex not yet contended (boot path locks itself).
func (e *envelopePathology) refreshEpochLocked(boot bool) error {
	if boot {
		e.epoch.mu.Lock()
		defer e.epoch.mu.Unlock()
	}
	id := e.currentEpochID()
	seed, err := derivePathologyEpoch(e.epoch.psk, id)
	if err != nil {
		// Fall back to envelope key material so Seal never hard-fails.
		seed = append([]byte(nil), e.key...)
		if len(seed) < 32 {
			seed = append(seed, make([]byte, 32-len(seed))...)
		}
	}
	t := buildPathologyEpochTable(e.cfg, seed, id, e.frameDCIDLen())
	e.epoch.cached = t
	e.epoch.have = true
	// Seal-side strategy / DCID follow the epoch.
	e.strategy = t.strategy
	if t.frame == pathologyFrameQUICShort && len(t.dcid) > 0 {
		e.dcid = append([]byte(nil), t.dcid...)
	}
	return nil
}

func buildPathologyEpochTable(cfg pathologyRuntimeConfig, seed []byte, epoch uint64, dcidLen int) pathologyEpochTable {
	if len(seed) < 32 {
		tmp := make([]byte, 32)
		copy(tmp, seed)
		seed = tmp
	}
	pol := pathologyPolicyForIntensity(cfg.Intensity)
	t := pathologyEpochTable{
		epoch: epoch,
		seed:  append([]byte(nil), seed...),
	}

	// padBudget ∈ [scaled/2, scaled] under intensity.
	budget := cfg.PadBudget
	if budget < 0 {
		budget = 0
	}
	if budget > 255 {
		budget = 255
	}
	scaled := int(float64(budget) * pol.padScale)
	if scaled < 0 {
		scaled = 0
	}
	if scaled > 255 {
		scaled = 255
	}
	if budget > 0 && scaled == 0 {
		scaled = 1
	}
	lo := scaled / 2
	span := scaled - lo
	t.padBudget = lo
	if span > 0 {
		t.padBudget = lo + int(seed[0])%((span)+1)
	}

	modes := cfg.PadProfile
	if len(modes) == 0 {
		modes = pathologyPersonas[cfg.Persona]
	}
	t.pads = expandPathologyPadQuanta(modes, t.padBudget, seed[1])

	idleModes := pathologyPersonas[cfg.IdlePersona]
	if cfg.IdlePersona == "" {
		idleModes = pathologyPersonas["dns-idle"]
	}
	t.idlePads = expandPathologyPadQuanta(idleModes, t.padBudget, seed[2])

	// strategy: auto → ascii|random only (balance deleted).
	switch cfg.Strategy {
	case "ascii":
		t.strategy = pathologyEntropyASCII
	case "random":
		t.strategy = pathologyEntropyRandom
	default: // auto
		if pol.asciiBias || seed[3]%2 == 0 {
			t.strategy = pathologyEntropyASCII
		} else {
			t.strategy = pathologyEntropyRandom
		}
	}
	if cfg.LowEntropy {
		t.strategy = pathologyEntropyASCII
	}

	// Frame: auto → intensity allowlist (+ mode prefer bias); explicit otherwise.
	switch cfg.Frame {
	case pathologyFrameAuto:
		t.frame = pickPathologyAutoFrame(pol.autoFrames, cfg.ModePrefer, seed[4])
	case pathologyFrameNone, "":
		t.frame = pathologyFrameNone
	default:
		t.frame = cfg.Frame
	}

	if dcidLen <= 0 {
		dcidLen = 8
	}
	if dcidLen > 20 {
		dcidLen = 20
	}
	t.dcid = make([]byte, dcidLen)
	pathologyStreamFill(t.dcid, seed, 0xDC, epoch)

	// Start decoy: honor explicit; else intensity-gated rare bias.
	t.startDecoy = cfg.StartDecoy
	if t.startDecoy == "" || t.startDecoy == "none" {
		if pol.decoyDenom > 0 && int(seed[5])%pol.decoyDenom == 0 {
			t.startDecoy = "quic-initial"
		} else {
			t.startDecoy = "none"
		}
	}

	t.startCover = cfg.StartCover
	if t.startCover == 0 && pol.coverMax > 0 {
		if t.startDecoy == "quic-initial" {
			t.startCover = 1 + int(seed[6])%pol.coverMax
			if t.startCover > pol.coverMax {
				t.startCover = pol.coverMax
			}
		} else if seed[7]%4 == 0 && pol.coverMax >= 1 {
			t.startCover = 1 + int(seed[6])%(pol.coverMax)
			if t.startCover > pol.coverMax {
				t.startCover = pol.coverMax
			}
		}
	}

	t.coverBody = make([]byte, pathologyCoverBodyMax)
	fillLowEntropyFromSeed(t.coverBody, seed)

	return t
}

func pickPathologyAutoFrame(allow []string, prefer string, b byte) string {
	if len(allow) == 0 {
		return pathologyFrameTLS13
	}
	if prefer != "" {
		for _, f := range allow {
			if f == prefer {
				// Prefer wins ~50% of epochs so rotation still varies.
				if b%2 == 0 {
					return prefer
				}
				break
			}
		}
	}
	return allow[int(b)%len(allow)]
}

// expandPathologyPadQuanta flattens weighted modes into a pad list (session-stable CDF).
func expandPathologyPadQuanta(modes []pathologyPadMode, budget int, shuffleByte byte) []int {
	if budget <= 0 {
		return []int{0}
	}
	if len(modes) == 0 {
		modes = pathologyPersonas["balanced"]
	}
	var out []int
	for _, m := range modes {
		if m.pad > budget || m.weight <= 0 {
			continue
		}
		for i := 0; i < m.weight; i++ {
			out = append(out, m.pad)
		}
	}
	if len(out) == 0 {
		return []int{budget}
	}
	// Light deterministic shuffle so different epochs don't share the same order.
	n := len(out)
	for i := 0; i < n; i++ {
		j := int(shuffleByte+byte(i)*13) % n
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func fillLowEntropyFromSeed(dst, seed []byte) {
	if len(dst) == 0 {
		return
	}
	const printable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,"
	for i := range dst {
		b := seed[i%len(seed)] ^ byte(i*31)
		dst[i] = printable[int(b)%len(printable)]
	}
}

func pickPathologyPadQuanta(pads []int, ctr uint64, dataLen int) int {
	if len(pads) == 0 {
		return 0
	}
	return pads[int((ctr+uint64(dataLen))%uint64(len(pads)))]
}
