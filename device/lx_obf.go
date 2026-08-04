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

// LxObfMorpher wraps a plain WireGuard UDP datagram on the way to/from the wire.
type LxObfMorpher interface {
	Seal(packet []byte) ([]byte, error)
	Open(packet []byte) ([]byte, error)
}

// lxObfCoverMorpher optionally emits decoy envelopes (T-START / T-IDLE).
type lxObfCoverMorpher interface {
	LxObfMorpher
	SealCover() ([]byte, error)
	StartCoverCount() int
	StartGap() (min, max time.Duration)
	CoverEvery() time.Duration
}

type lxObfState struct {
	enabled   atomic.Bool
	mu        sync.RWMutex
	morpher   LxObfMorpher
	cfg       lxObfRuntimeConfig
	hasKey    bool
	lastCover atomic.Int64 // unix nano of last idle cover send
}

func (device *Device) lxObfEnabled() bool {
	return device.lxObf.enabled.Load()
}

func (device *Device) lxObfSeal(packet []byte) ([]byte, error) {
	device.lxObf.mu.RLock()
	m := device.lxObf.morpher
	device.lxObf.mu.RUnlock()
	if m == nil {
		return packet, nil
	}
	return m.Seal(packet)
}

func (device *Device) lxObfOpen(packet []byte) ([]byte, error) {
	device.lxObf.mu.RLock()
	m := device.lxObf.morpher
	device.lxObf.mu.RUnlock()
	if m == nil {
		return packet, nil
	}
	return m.Open(packet)
}

func (device *Device) lxObfCover() lxObfCoverMorpher {
	device.lxObf.mu.RLock()
	defer device.lxObf.mu.RUnlock()
	c, _ := device.lxObf.morpher.(lxObfCoverMorpher)
	return c
}

func (device *Device) setLxObfMorpherConfig(m LxObfMorpher, cfg lxObfRuntimeConfig, hasKey bool) {
	device.lxObf.mu.Lock()
	defer device.lxObf.mu.Unlock()
	device.lxObf.morpher = m
	device.lxObf.cfg = cfg
	device.lxObf.hasKey = hasKey
	device.lxObf.enabled.Store(m != nil)
}

// lxObfBuildStartCovers returns already-sealed decoy datagrams for T-START.
func (device *Device) lxObfBuildStartCovers() [][]byte {
	c := device.lxObfCover()
	if c == nil {
		return nil
	}
	n := c.StartCoverCount()
	if n <= 0 {
		return nil
	}
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		pkt, err := c.SealCover()
		if err != nil {
			device.log.Verbosef("lx_obf: start cover seal failed: %v", err)
			continue
		}
		out = append(out, pkt)
	}
	return out
}

func (device *Device) lxObfStartGapSleep(index int) {
	c := device.lxObfCover()
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

// lxObfMaybeIdleCover returns one sealed cover when cover_interval elapsed.
// Interval is lightly jittered (±20%) so mid-session covers are not metronomic.
func (device *Device) lxObfMaybeIdleCover() []byte {
	c := device.lxObfCover()
	if c == nil {
		return nil
	}
	every := c.CoverEvery()
	if every <= 0 {
		return nil
	}
	now := time.Now().UnixNano()
	last := device.lxObf.lastCover.Load()
	effective := every
	if last != 0 {
		// ±20% jitter derived from last timestamp (no extra lock / rand).
		j := every / 5
		if j > 0 {
			effective = every - j + time.Duration(last%int64(2*j+1))
		}
	}
	if last != 0 && now-last < int64(effective) {
		return nil
	}
	if !device.lxObf.lastCover.CompareAndSwap(last, now) {
		return nil
	}
	pkt, err := c.SealCover()
	if err != nil {
		return nil
	}
	return pkt
}

func isLxObfCover(err error) bool {
	return errors.Is(err, errLxObfCover)
}
