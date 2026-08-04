/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-PROBE replay cache for envelope nonces.
 */

package device

import "sync"

const pathologyReplayCap = 2048

type pathologyReplayCache struct {
	mu    sync.Mutex
	seen  map[[12]byte]struct{}
	order [pathologyReplayCap][12]byte
	pos   int
	full  bool
}

func newPathologyReplayCache() *pathologyReplayCache {
	return &pathologyReplayCache{seen: make(map[[12]byte]struct{}, pathologyReplayCap)}
}

// checkAndAdd returns false if nonce was already observed (replay).
func (c *pathologyReplayCache) checkAndAdd(nonce []byte) bool {
	if c == nil || len(nonce) != 12 {
		return true
	}
	var key [12]byte
	copy(key[:], nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[key]; ok {
		return false
	}
	if c.full {
		old := c.order[c.pos]
		delete(c.seen, old)
	}
	c.order[c.pos] = key
	c.seen[key] = struct{}{}
	c.pos++
	if c.pos >= pathologyReplayCap {
		c.pos = 0
		c.full = true
	}
	return true
}
