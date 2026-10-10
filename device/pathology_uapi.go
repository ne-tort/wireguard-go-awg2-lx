/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 084 — AWG↔PathologyWG mutual exclusion guards.
 *
 * The pathology_* UAPI parse/get surface is gone (the fork injects a ready
 * morpher via Device.SetPathologyMorpher); what remains here is the two-way
 * exclusion with AmneziaWG knobs, which is device state and must stay in this
 * module.
 */

package device

import (
	"errors"
	"fmt"
)

// awgKnobsConflictWithPathology reports whether any AmneziaWG obfuscation knob that
// changes the wire (junk, S-padding, CPS, HP, CPA) is active on the device.
// Default magic headers (types 1–4) alone are plain WG and do not conflict.
func (device *Device) awgKnobsConflictWithPathology() error {
	if device.junk.count.Load() != 0 || device.junk.min.Load() != 0 || device.junk.max.Load() != 0 {
		return errors.New("pathologywg cannot be combined with AmneziaWG junk (jc/jmin/jmax)")
	}
	if device.paddings.init.Load() != 0 || device.paddings.response.Load() != 0 ||
		device.paddings.cookie.Load() != 0 || device.paddings.transport.Load() != 0 {
		return errors.New("pathologywg cannot be combined with AmneziaWG padding (s1–s4)")
	}
	for i, p := range device.ipackets {
		if p != nil {
			return fmt.Errorf("pathologywg cannot be combined with AmneziaWG CPS (i%d)", i+1)
		}
	}
	device.headerProtection.RLock()
	hpSet := !device.headerProtection.key.IsZero()
	device.headerProtection.RUnlock()
	if hpSet {
		return errors.New("pathologywg cannot be combined with AmneziaWG header_protection_key")
	}
	if !device.contentPaddingAddition.Load().IsZero() {
		return errors.New("pathologywg cannot be combined with AmneziaWG content_padding_addition")
	}
	if device.randomTrailers.Load() {
		return errors.New("pathology cannot be combined with AmneziaWG random_trailers")
	}
	if device.disableCookies.Load() {
		return errors.New("pathology cannot be combined with AmneziaWG disable_cookies")
	}
	return nil
}

func (d *ipcSetDevice) pendingPaddingOrHP() bool {
	return d.paddings.init != 0 || d.paddings.response != 0 ||
		d.paddings.cookie != 0 || d.paddings.transport != 0 ||
		!d.headerProtectionKey.IsZero()
}

func (device *Device) errIfPathologyBlocksAWG(what string) error {
	if device.pathologyEnabled() {
		return fmt.Errorf("AmneziaWG %s cannot be set while pathologywg is enabled", what)
	}
	return nil
}
