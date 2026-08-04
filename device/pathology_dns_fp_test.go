/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 */

package device

import (
	"bytes"
	"testing"
)

// Regression: DNS Transaction ID used to collide with envelope version bytes
// (~3/256), causing Open to treat framed packets as raw envelopes and drop them.
func TestDNSFrameNoEnvelopeVersionCollision(t *testing.T) {
	psk := []byte("dns-fp-rate-key-material-xxxxxx")
	cfg := testCfg("balanced", 64)
	cfg.Frame = pathologyFrameDNS
	cfg.Cipher = pathologyCipherStream
	cfg.Dialog = pathologyDialogOff
	m, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sizes := []int{16, 32, 148, 1220, 1280}
	const N = 5000
	for _, sz := range sizes {
		var openFail, dialogFP int
		wg := bytes.Repeat([]byte{0xab}, sz)
		for i := 0; i < N; i++ {
			wg[0] = byte(i)
			wg[1] = byte(i >> 8)
			sealed, err := m.Seal(wg)
			if err != nil {
				t.Fatal(err)
			}
			if isPathologyEnvelopeVersion(sealed[0]) {
				t.Fatalf("sz=%d i=%d: DNS ID[0]=0x%02x collides with envelope ver", sz, i, sealed[0])
			}
			if looksLikePathologyDNSQuery(sealed) {
				dialogFP++
			}
			if _, hit := m.MaybeDialogReply(sealed); hit {
				dialogFP++
			}
			out, err := m.Open(sealed)
			if err != nil || !bytes.Equal(out, wg) {
				openFail++
			}
		}
		if openFail != 0 || dialogFP != 0 {
			t.Fatalf("sz=%d: openFail=%d dialogFP=%d (want 0)", sz, openFail, dialogFP)
		}
	}
}

func TestDNSFrameOpenAcceptsLegacyVersionID(t *testing.T) {
	// Pre-fix peers may still emit ID[0] ∈ {0x02,0x03,0x04}; Open must peel +12.
	psk := []byte("dns-legacy-id-key-material-xxx")
	cfg := testCfg("balanced", 16)
	cfg.Frame = pathologyFrameDNS
	cfg.Cipher = pathologyCipherStream
	cfg.Dialog = pathologyDialogOff
	m, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	wg := bytes.Repeat([]byte{0xcd}, 64)
	for _, ver := range []byte{0x02, 0x03, 0x04} {
		sealed, err := m.Seal(wg)
		if err != nil {
			t.Fatal(err)
		}
		pkt := append([]byte(nil), sealed...)
		pkt[0] = ver
		out, err := m.Open(pkt)
		if err != nil || !bytes.Equal(out, wg) {
			t.Fatalf("legacy ID[0]=0x%02x: err=%v", ver, err)
		}
	}
}

func BenchmarkSealOpenFrames(b *testing.B) {
	psk := []byte("bench-frame-key-material-xxxxxx")
	wg := bytes.Repeat([]byte{9}, 1280)
	for _, frame := range []string{"tls13", "quic-short", "dns", "stun"} {
		b.Run(frame, func(b *testing.B) {
			cfg := testCfg("balanced", 32)
			cfg.Frame = frame
			cfg.Cipher = pathologyCipherStream
			cfg.Dialog = pathologyDialogOff
			m, err := newEnvelopePathology(psk, cfg)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(wg)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s, err := m.Seal(wg)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := m.Open(s); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
