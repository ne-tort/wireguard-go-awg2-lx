/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — UAPI helpers for pathology.
 */

package device

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// parsePathologyUAPI accepts true/false/1/0 (case-insensitive).
func parsePathologyUAPI(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		if v, err := strconv.ParseBool(value); err == nil {
			return v, nil
		}
		return false, fmt.Errorf("invalid pathology value %q (want true/false/1/0)", value)
	}
}

// parsePathologyKeyUAPI accepts hex-encoded PSK bytes (any length ≥ 1).
func parsePathologyKeyUAPI(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "set" {
		return nil, fmt.Errorf("pathology_key must be hex-encoded secret")
	}
	key, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("pathology_key hex: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("pathology_key is empty")
	}
	return key, nil
}

// awgKnobsConflictWithPathology reports whether any AmneziaWG obfuscation knob that
// changes the wire (junk, S-padding, CPS, HP, CPA) is active on the device.
// Default magic headers (types 1–4) alone are plain WG and do not conflict.
func (device *Device) awgKnobsConflictWithPathology() error {
	if device.junk.count.Load() != 0 || device.junk.min.Load() != 0 || device.junk.max.Load() != 0 {
		return errors.New("pathology cannot be combined with AmneziaWG junk (jc/jmin/jmax)")
	}
	if device.paddings.init.Load() != 0 || device.paddings.response.Load() != 0 ||
		device.paddings.cookie.Load() != 0 || device.paddings.transport.Load() != 0 {
		return errors.New("pathology cannot be combined with AmneziaWG padding (s1–s4)")
	}
	for i, p := range device.ipackets {
		if p != nil {
			return fmt.Errorf("pathology cannot be combined with AmneziaWG CPS (i%d)", i+1)
		}
	}
	device.headerProtection.RLock()
	hpSet := !device.headerProtection.key.IsZero()
	device.headerProtection.RUnlock()
	if hpSet {
		return errors.New("pathology cannot be combined with AmneziaWG header_protection_key")
	}
	if !device.contentPaddingAddition.Load().IsZero() {
		return errors.New("pathology cannot be combined with AmneziaWG content_padding_addition")
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
		return fmt.Errorf("AmneziaWG %s cannot be set while pathology is enabled", what)
	}
	return nil
}
