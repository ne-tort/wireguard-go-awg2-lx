/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// MbpsToBps converts integer megabits/sec to bytes/sec (Hy2 / sing-box convention).
const MbpsToBps = 125_000

// BandwidthLimiter is a token-bucket byte rate limiter.
// rateBps == 0 means disabled (Wait is a no-op, no locks on the hot path).
type BandwidthLimiter struct {
	rateBps atomic.Int64 // bytes per second; 0 = off

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// SetMbps sets the limit in Mbps. 0 disables the limiter.
func (l *BandwidthLimiter) SetMbps(mbps int) {
	if mbps < 0 {
		mbps = 0
	}
	rate := int64(mbps) * MbpsToBps
	l.rateBps.Store(rate)
	if rate == 0 {
		l.mu.Lock()
		l.tokens = 0
		l.last = time.Time{}
		l.mu.Unlock()
	}
}

// Mbps returns the configured limit in Mbps (0 = unlimited).
func (l *BandwidthLimiter) Mbps() int {
	rate := l.rateBps.Load()
	if rate <= 0 {
		return 0
	}
	return int(rate / MbpsToBps)
}

// Enabled reports whether Wait will enforce a limit.
func (l *BandwidthLimiter) Enabled() bool {
	return l.rateBps.Load() > 0
}

// Wait blocks until n bytes may be transferred under the configured rate.
// When disabled or n <= 0, returns immediately without locking.
func (l *BandwidthLimiter) Wait(n int) {
	if n <= 0 {
		return
	}
	rate := l.rateBps.Load()
	if rate <= 0 {
		return
	}
	need := float64(n)
	maxTokens := float64(rate) // ~1s burst

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if l.last.IsZero() {
		l.last = now
		l.tokens = maxTokens
	} else {
		elapsed := now.Sub(l.last).Seconds()
		l.last = now
		l.tokens += elapsed * float64(rate)
		if l.tokens > maxTokens {
			l.tokens = maxTokens
		}
	}

	for l.tokens < need {
		// Re-check rate under lock in case SetMbps(0) raced in.
		rate = l.rateBps.Load()
		if rate <= 0 {
			l.tokens = 0
			l.last = time.Time{}
			return
		}
		maxTokens = float64(rate)
		deficit := need - l.tokens
		wait := time.Duration(deficit / float64(rate) * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		l.mu.Unlock()
		time.Sleep(wait)
		l.mu.Lock()
		now = time.Now()
		elapsed := now.Sub(l.last).Seconds()
		l.last = now
		rate = l.rateBps.Load()
		if rate <= 0 {
			l.tokens = 0
			l.last = time.Time{}
			return
		}
		l.tokens += elapsed * float64(rate)
		if l.tokens > maxTokens {
			l.tokens = maxTokens
		}
	}
	l.tokens -= need
}

// BandwidthPair holds separate upload (TX) and download (RX) limiters.
type BandwidthPair struct {
	up   BandwidthLimiter
	down BandwidthLimiter
}

func (p *BandwidthPair) SetMbps(up, down int) {
	p.up.SetMbps(up)
	p.down.SetMbps(down)
}

func (p *BandwidthPair) SetUpMbps(mbps int)   { p.up.SetMbps(mbps) }
func (p *BandwidthPair) SetDownMbps(mbps int) { p.down.SetMbps(mbps) }
func (p *BandwidthPair) UpMbps() int          { return p.up.Mbps() }
func (p *BandwidthPair) DownMbps() int        { return p.down.Mbps() }

func (p *BandwidthPair) WaitUp(n int)   { p.up.Wait(n) }
func (p *BandwidthPair) WaitDown(n int) { p.down.Wait(n) }

// shapeUpload enforces peer then device upload caps (both must allow; min rate wins).
func (peer *Peer) shapeUpload(n int) {
	if n <= 0 {
		return
	}
	peer.bandwidth.WaitUp(n)
	peer.device.bandwidth.WaitUp(n)
}

// shapeDownload enforces peer then device download caps.
func (peer *Peer) shapeDownload(n int) {
	if n <= 0 {
		return
	}
	peer.bandwidth.WaitDown(n)
	peer.device.bandwidth.WaitDown(n)
}

func parseMbpsUAPI(value string) (int, error) {
	mbps, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, err
	}
	return int(mbps), nil
}
