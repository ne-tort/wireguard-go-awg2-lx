/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-PROBE replay cache for envelope nonces.
 */

package device

import "sync"

const lxObfReplayCap = 2048

type lxObfReplayCache struct {
	mu   sync.Mutex
	seen map[[12]byte]struct{}
	order [][12]byte
}

func newLxObfReplayCache() *lxObfReplayCache {
	return &lxObfReplayCache{seen: make(map[[12]byte]struct{}, lxObfReplayCap)}
}

// checkAndAdd returns false if nonce was already observed (replay).
func (c *lxObfReplayCache) checkAndAdd(nonce []byte) bool {
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
	if len(c.order) >= lxObfReplayCap {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.seen, old)
	}
	c.seen[key] = struct{}{}
	c.order = append(c.order, key)
	return true
}
