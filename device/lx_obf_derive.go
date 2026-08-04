/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-DERIVE session key from shared PSK.
 */

package device

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	lxObfHKDFSalt = "sing-box-lx/lx-obf/v1"
	lxObfHKDFInfo = "envelope-aead-key"
	lxObfKeySize  = 32
)

// deriveLxObfKey expands a shared PSK into a 32-byte ChaCha20-Poly1305 key.
// Seed is never placed on the wire (TECHNIQUES T-DERIVE).
func deriveLxObfKey(psk []byte) ([]byte, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("lx_obf key is empty")
	}
	r := hkdf.New(sha256.New, psk, []byte(lxObfHKDFSalt), []byte(lxObfHKDFInfo))
	out := make([]byte, lxObfKeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
