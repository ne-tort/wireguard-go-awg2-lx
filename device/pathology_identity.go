/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — identity (passthrough) morpher.
 */

package device

// identityPathology is a no-op morpher: Seal/Open return the packet unchanged.
// Used by the skeleton to prove SendBuffers / receive hooks without changing wire bytes.
type identityPathology struct{}

func (identityPathology) Seal(packet []byte) ([]byte, error) { return packet, nil }

func (identityPathology) Open(packet []byte) ([]byte, error) { return packet, nil }

func newIdentityPathology() PathologyMorpher { return identityPathology{} }
