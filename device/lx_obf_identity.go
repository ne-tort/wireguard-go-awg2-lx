/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — identity (passthrough) morpher.
 */

package device

// identityLxObf is a no-op morpher: Seal/Open return the packet unchanged.
// Used by the skeleton to prove SendBuffers / receive hooks without changing wire bytes.
type identityLxObf struct{}

func (identityLxObf) Seal(packet []byte) ([]byte, error) { return packet, nil }

func (identityLxObf) Open(packet []byte) ([]byte, error) { return packet, nil }

func newIdentityLxObf() LxObfMorpher { return identityLxObf{} }
