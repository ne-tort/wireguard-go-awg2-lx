/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — T-DERIVE session key + epoch morph seed from shared PSK.
 */

package device

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	pathologyHKDFSalt      = "sing-box-lx/pathology/v1"
	pathologyHKDFInfo      = "envelope-aead-key"
	pathologyHKDFInfoEpoch = "morph-epoch-v1"
	pathologyKeySize       = 32
)

// derivePathologyKey expands a shared PSK into a 32-byte envelope key.
// Seed is never placed on the wire (TECHNIQUES T-DERIVE).
func derivePathologyKey(psk []byte) ([]byte, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("pathology key is empty")
	}
	r := hkdf.New(sha256.New, psk, []byte(pathologyHKDFSalt), []byte(pathologyHKDFInfo))
	out := make([]byte, pathologyKeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// derivePathologyEpoch expands PSK + epoch bucket into a 32-byte morph seed (T-EPOCH).
func derivePathologyEpoch(psk []byte, epoch uint64) ([]byte, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("pathology key is empty")
	}
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], epoch)
	info := append([]byte(pathologyHKDFInfoEpoch), ep[:]...)
	r := hkdf.New(sha256.New, psk, []byte(pathologyHKDFSalt), info)
	out := make([]byte, pathologyKeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
