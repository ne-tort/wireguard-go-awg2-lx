/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — outer obfuscation morpher (parallel to AmneziaWG).
 */

package device

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// PathologyMorpher wraps a plain WireGuard UDP datagram on the way to/from the wire.
type PathologyMorpher interface {
	Seal(packet []byte) ([]byte, error)
	Open(packet []byte) ([]byte, error)
}

// pathologyCoverMorpher optionally emits decoy envelopes (T-START / T-IDLE / T-DIALOG).
type pathologyCoverMorpher interface {
	PathologyMorpher
	SealCover() ([]byte, error)
	StartCoverCount() int
	StartGap() (min, max time.Duration)
	CoverEvery() time.Duration
	StartDecoyMode() string
	BuildQUICInitialDecoy() ([]byte, error)
	BuildStartDialog() []pathologyDialogStep
	MaybeDialogReply(packet []byte) (reply []byte, handled bool)
}

type pathologyState struct {
	enabled   atomic.Bool
	mu        sync.RWMutex
	morpher   PathologyMorpher
	cfg       pathologyRuntimeConfig
	hasKey    bool
	lastCover atomic.Int64 // unix nano of last idle cover send
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

func (device *Device) pathologyCover() pathologyCoverMorpher {
	device.pathology.mu.RLock()
	defer device.pathology.mu.RUnlock()
	c, _ := device.pathology.morpher.(pathologyCoverMorpher)
	return c
}

func (device *Device) setPathologyMorpherConfig(m PathologyMorpher, cfg pathologyRuntimeConfig, hasKey bool) {
	device.pathology.mu.Lock()
	defer device.pathology.mu.Unlock()
	device.pathology.morpher = m
	device.pathology.cfg = cfg
	device.pathology.hasKey = hasKey
	device.pathology.enabled.Store(m != nil)
}

// pathologyMaybeDialogReply returns a legend response for T-DIALOG start requests.
func (device *Device) pathologyMaybeDialogReply(packet []byte) ([]byte, bool) {
	c := device.pathologyCover()
	if c == nil {
		return nil, false
	}
	return c.MaybeDialogReply(packet)
}

// pathologyRunStartDialog sends polite req steps (and RTT-scale waits) before initiation.
// Falls back to legacy cover burst when dialog is off but start_cover>0.
func (device *Device) pathologyRunStartDialog(send func(pkt []byte)) {
	c := device.pathologyCover()
	if c == nil {
		return
	}
	steps := c.BuildStartDialog()
	if len(steps) > 0 {
		for _, s := range steps {
			if len(s.Packet) == 0 {
				continue
			}
			send(s.Packet)
			if s.WaitMs > 0 {
				time.Sleep(time.Duration(s.WaitMs) * time.Millisecond)
			}
		}
		return
	}
	// Legacy T-START covers when dialog=off.
	n := c.StartCoverCount()
	if n <= 0 {
		return
	}
	decoy := c.StartDecoyMode() == "quic-initial"
	for i := 0; i < n; i++ {
		var pkt []byte
		var err error
		if decoy && i == 0 {
			pkt, err = c.BuildQUICInitialDecoy()
		} else {
			pkt, err = c.SealCover()
		}
		if err != nil {
			device.log.Verbosef("pathology: start cover seal failed: %v", err)
			continue
		}
		if i > 0 {
			device.pathologyStartGapSleep(i)
		}
		send(pkt)
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
		nsec := time.Now().UnixNano()
		span := int64(max - min)
		if span > 0 {
			d = min + time.Duration(nsec%span)
		}
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
	return errors.Is(err, errPathologyCover)
}
