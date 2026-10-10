/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 084 — PathologyWG outer morpher hook (parallel to AmneziaWG).
 *
 * This module keeps ONLY the hook surface — the interfaces, the injector and
 * the send/recv call helpers. The morpher implementation (SSOT envelope,
 * epoch appearance, frames, cover/dialog builders, T-VARIANT rotation) lives
 * fork-side in sing-box transport/wireguard on top of
 * common/pathology/morph, so there is exactly one envelope/crypto engine and
 * this submodule never imports sing-box (module cycle). There are no
 * pathology_* UAPI lines: the fork injects a ready morpher through
 * Device.SetPathologyMorpher.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// PathologyMorpher wraps a plain WireGuard UDP datagram on the way to/from the
// wire. Implementations live outside this module; the interface is defined here
// so the device depends on nothing but its own hook surface.
type PathologyMorpher interface {
	Seal(packet []byte) ([]byte, error)
	Open(packet []byte) ([]byte, error)
}

// PathologyDialogStep is one outbound datagram of a polite start script
// (T-DIALOG / T-START), pre-built by the morpher and paced by the device.
type PathologyDialogStep struct {
	Packet []byte
	WaitMs int // RTT-scale pause after send before next step / initiation
}

// PathologyCoverMorpher optionally emits decoy envelopes and start legends
// (T-START / T-IDLE / T-DIALOG). The device type-asserts the injected
// PathologyMorpher to this interface; a morpher without it simply has no
// cover behaviour (e.g. the keyless identity passthrough).
type PathologyCoverMorpher interface {
	PathologyMorpher
	SealCover() ([]byte, error)
	StartCoverCount() int
	StartGap() (min, max time.Duration)
	CoverEvery() time.Duration
	StartDecoyMode() string
	BuildStartDecoy() ([]byte, error)
	BuildStartDialog() []PathologyDialogStep
	MaybeDialogReply(packet []byte) (reply []byte, handled bool)
}

// PathologyVariantMorpher optionally supports failure-driven appearance
// rotation (T-VARIANT, SPEC 084): when handshake initiations keep going
// unanswered, the device asks the morpher to switch its Seal-side pattern
// (frame legend, pad CDF picks, dialog/decoy choices, appearance seed) so the
// next retry presents a different shape to whatever is dropping the old one.
// The receiving Open is pattern-agnostic (soft-peel + AEAD tag decides), so
// rotation is unilateral — no renegotiation, no peer lockstep. Returns whether
// the appearance actually changed.
type PathologyVariantMorpher interface {
	PathologyMorpher
	RotateVariant(trigger string) bool
}

// ErrPathologyCover marks a packet that is cover (decoy envelope, start legend,
// dialog response) rather than a WireGuard message; the receive path drops it
// silently. Morphers must return it via errors.Is-compatible wrapping.
var ErrPathologyCover = errors.New("pathology: cover packet")

// pathologyVariantDebounceNs is the minimum spacing between two T-VARIANT
// rotations: one failure burst (multi-peer races, retry + give-up triggers of
// the same series) advances the variant once, while a sustained outage keeps
// rotating on every retry cycle (~RekeyTimeout apart).
const pathologyVariantDebounceNs = int64(4 * time.Second)

type pathologyState struct {
	enabled    atomic.Bool
	mu         sync.RWMutex
	morpher    PathologyMorpher
	lastCover  atomic.Int64 // unix nano of last idle cover send
	lastRotate atomic.Int64 // unix nano of last T-VARIANT rotation (debounce)
}

// SetPathologyMorpher injects the fork-side morpher, or nil to disable the
// hook. It is the only pathology configuration surface. A non-nil morpher is
// rejected while wire-changing AmneziaWG knobs are active — the two
// obfuscators would corrupt each other's output.
func (device *Device) SetPathologyMorpher(m PathologyMorpher) error {
	if m != nil {
		if err := device.awgKnobsConflictWithPathology(); err != nil {
			return err
		}
		// SPEC 084: the WARP reserved-byte rewrite stamps UDP[1:4] of every
		// outgoing datagram and clears it on receive — inside a sealed
		// envelope those are nonce bytes, so the rewrite silently corrupts
		// the morpher (AEAD fails on both ends; plain WG never notices
		// because its type-word bytes 1-3 are zero anyway). Force the skip
		// here so no consumer has to remember SetSkipReserved; found the
		// hard way in the bare-device lab.
		device.net.RLock()
		if skipper, ok := device.net.bind.(interface{ SetSkipReserved(bool) }); ok {
			skipper.SetSkipReserved(true)
		}
		device.net.RUnlock()
	}
	device.pathology.mu.Lock()
	defer device.pathology.mu.Unlock()
	device.pathology.morpher = m
	device.pathology.enabled.Store(m != nil)
	return nil
}

func (device *Device) pathologyEnabled() bool {
	return device.pathology.enabled.Load()
}

func (device *Device) pathologySeal(packet []byte) ([]byte, error) {
	device.pathology.mu.RLock()
	m := device.pathology.morpher
	device.pathology.mu.RUnlock()
	if m == nil {
		return packet, nil
	}
	return m.Seal(packet)
}

func (device *Device) pathologyOpen(packet []byte) ([]byte, error) {
	device.pathology.mu.RLock()
	m := device.pathology.morpher
	device.pathology.mu.RUnlock()
	if m == nil {
		return packet, nil
	}
	return m.Open(packet)
}

func (device *Device) pathologyCover() PathologyCoverMorpher {
	device.pathology.mu.RLock()
	defer device.pathology.mu.RUnlock()
	c, _ := device.pathology.morpher.(PathologyCoverMorpher)
	return c
}

// pathologyMaybeDialogReply returns a legend response for T-DIALOG start requests.
func (device *Device) pathologyMaybeDialogReply(packet []byte) ([]byte, bool) {
	c := device.pathologyCover()
	if c == nil {
		return nil, false
	}
	return c.MaybeDialogReply(packet)
}

// pathologyMaybeRotateVariant is the T-VARIANT trigger (SPEC 084): called from
// the handshake retry/give-up paths when initiations keep going unanswered.
// Debounced per device; a no-op when the injected morpher does not rotate.
func (device *Device) pathologyMaybeRotateVariant(trigger string) {
	device.pathology.mu.RLock()
	m := device.pathology.morpher
	device.pathology.mu.RUnlock()
	v, ok := m.(PathologyVariantMorpher)
	if !ok {
		return
	}
	now := time.Now().UnixNano()
	last := device.pathology.lastRotate.Load()
	if last != 0 && now-last < pathologyVariantDebounceNs {
		return
	}
	if !device.pathology.lastRotate.CompareAndSwap(last, now) {
		return
	}
	if v.RotateVariant(trigger) {
		device.log.Verbosef("pathology: morph variant rotated (trigger %s)", trigger)
	}
}

// pathologyStartPrelude pre-builds the T-DIALOG / T-START datagrams for one
// handshake attempt and returns a runner that sends them with RTT-scale waits,
// or nil when there is nothing to run (dialog off and start_cover=0). Packets
// are built synchronously (fresh crypto/rand identifiers per attempt, N5-4);
// the runner sleeps and MUST only be invoked from a dedicated goroutine —
// never from RoutineReadFromTUN / RoutineSequentialReceiver / SendStagedPackets
// call stacks (N5-4: a 40–250 ms sleep there stalls the whole device).
func (device *Device) pathologyStartPrelude() func(send func(pkt []byte)) {
	c := device.pathologyCover()
	if c == nil {
		return nil
	}
	if steps := c.BuildStartDialog(); len(steps) > 0 {
		return func(send func(pkt []byte)) {
			for _, s := range steps {
				if len(s.Packet) == 0 {
					continue
				}
				send(s.Packet)
				if s.WaitMs > 0 {
					time.Sleep(time.Duration(s.WaitMs) * time.Millisecond)
				}
			}
		}
	}
	// Legacy T-START covers when dialog=off.
	n := c.StartCoverCount()
	if n <= 0 {
		return nil
	}
	decoy := c.StartDecoyMode() != "" && c.StartDecoyMode() != "none"
	pkts := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		var pkt []byte
		var err error
		if decoy && i == 0 {
			pkt, err = c.BuildStartDecoy()
		} else {
			pkt, err = c.SealCover()
		}
		if err != nil {
			device.log.Verbosef("pathology: start cover seal failed: %v", err)
			continue
		}
		pkts = append(pkts, pkt)
	}
	if len(pkts) == 0 {
		return nil
	}
	return func(send func(pkt []byte)) {
		for i, pkt := range pkts {
			if i > 0 {
				device.pathologyStartGapSleep(i)
			}
			send(pkt)
		}
	}
}

func (device *Device) pathologyStartGapSleep(index int) {
	c := device.pathologyCover()
	if c == nil || index <= 0 {
		return
	}
	min, max := c.StartGap()
	if max <= 0 {
		return
	}
	d := min
	if max > min {
		d = min + time.Duration(pathologyRandIntn(int(max-min)))
	}
	if d > 0 {
		time.Sleep(d)
	}
}

// pathologyMaybeIdleCover returns one sealed cover when cover_interval elapsed.
// Interval is lightly jittered (±20%) so mid-session covers are not metronomic.
func (device *Device) pathologyMaybeIdleCover() []byte {
	c := device.pathologyCover()
	if c == nil {
		return nil
	}
	every := c.CoverEvery()
	if every <= 0 {
		return nil
	}
	now := time.Now().UnixNano()
	last := device.pathology.lastCover.Load()
	effective := every
	if last != 0 {
		j := every / 5
		if j > 0 {
			effective = every - j + time.Duration(last%int64(2*j+1))
		}
	}
	if last != 0 && now-last < int64(effective) {
		return nil
	}
	if !device.pathology.lastCover.CompareAndSwap(last, now) {
		return nil
	}
	pkt, err := c.SealCover()
	if err != nil {
		return nil
	}
	return pkt
}

func isPathologyCover(err error) bool {
	return errors.Is(err, ErrPathologyCover)
}

// pathologyRandIntn returns a crypto/rand int in [0,n) (n>0).
func pathologyRandIntn(n int) int {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b[:])) % n
}
