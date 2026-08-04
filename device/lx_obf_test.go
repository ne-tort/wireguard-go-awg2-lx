/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 — unit tests for identity / envelope / cover / conflict.
 */

package device

import (
	"bytes"
	"errors"
	"testing"
)

func TestIdentityLxObfRoundTrip(t *testing.T) {
	m := newIdentityLxObf()
	in := []byte{1, 2, 3, 4, 5}
	sealed, err := m.Seal(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) != string(in) {
		t.Fatalf("Seal changed bytes")
	}
	opened, err := m.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != string(in) {
		t.Fatalf("Open changed bytes")
	}
}

func TestParseLxObfUAPI(t *testing.T) {
	got, err := parseLxObfUAPI("true")
	if err != nil || !got {
		t.Fatal(err, got)
	}
	_, err = parseLxObfUAPI("nope")
	if err == nil {
		t.Fatal("expected err")
	}
}

func TestLxObfConflictsWithJunk(t *testing.T) {
	dev := &Device{}
	dev.junk.count.Store(3)
	if err := dev.awgKnobsConflictWithLxObf(); err == nil {
		t.Fatal("expected conflict")
	}
}

func testCfg(persona string, pad int) lxObfRuntimeConfig {
	cfg := defaultLxObfRuntimeConfig()
	cfg.Persona = persona
	cfg.PadBudget = pad
	return cfg
}

func TestEnvelopeRoundTripAndLengthHide(t *testing.T) {
	psk := []byte("client-server-shared-secret-32b!!")
	cli, err := newEnvelopeLxObf(psk, testCfg("quic-h3", 64))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newEnvelopeLxObf(psk, testCfg("balanced", 96))
	if err != nil {
		t.Fatal(err)
	}
	wgSizes := []int{32, 64, 92, 148, 200, 1200}
	for _, n := range wgSizes {
		wg := bytes.Repeat([]byte{byte(n)}, n)
		sealed, err := cli.Seal(wg)
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed) == n {
			t.Fatalf("outer length still equals WG size %d", n)
		}
		for _, classic := range []int{32, 64, 92, 148} {
			if len(sealed) == classic {
				t.Fatalf("outer collapsed to classic %d", classic)
			}
		}
		opened, err := srv.Open(sealed)
		if err != nil {
			t.Fatalf("open size=%d: %v", n, err)
		}
		if !bytes.Equal(opened, wg) {
			t.Fatalf("round-trip mismatch size=%d", n)
		}
	}
}

func TestEnvelopeCoverSilent(t *testing.T) {
	psk := []byte("cover-test-key-material-xxxxxxx")
	m, err := newEnvelopeLxObf(psk, testCfg("dns-idle", 32))
	if err != nil {
		t.Fatal(err)
	}
	cover, err := m.SealCover()
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Open(cover)
	if !errors.Is(err, errLxObfCover) {
		t.Fatalf("want cover err, got %v", err)
	}
}

func TestEnvelopeCustomProfile(t *testing.T) {
	psk := []byte("profile-test-key-material-xxxxx")
	cfg := testCfg("custom", 80)
	cfg.PadProfile = []lxObfPadMode{{pad: 10, weight: 1}, {pad: 20, weight: 1}}
	m, err := newEnvelopeLxObf(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		sealed, err := m.Seal(bytes.Repeat([]byte{1}, 64))
		if err != nil {
			t.Fatal(err)
		}
		pad := len(sealed) - (64 + LxObfFixedOverhead())
		if pad != 10 && pad != 20 && pad != 11 && pad != 21 {
			// avoidClassic may bump by 1
			if pad < 10 || pad > 22 {
				t.Fatalf("unexpected pad %d", pad)
			}
		}
	}
}

func TestEnvelopeWrongKey(t *testing.T) {
	a, err := newEnvelopeLxObf([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), testCfg("balanced", 32))
	if err != nil {
		t.Fatal(err)
	}
	b, err := newEnvelopeLxObf([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), testCfg("balanced", 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.Seal([]byte("hello-wireguard-packet!!!!"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestEnvelopeReplayRejected(t *testing.T) {
	m, err := newEnvelopeLxObf([]byte("replay-test-key-material-xxxxxx"), testCfg("dns-idle", 16))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := m.Seal(bytes.Repeat([]byte{7}, 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Open(sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Open(sealed); err == nil {
		t.Fatal("expected replay rejection")
	}
}

func TestDeriveStable(t *testing.T) {
	k1, _ := deriveLxObfKey([]byte("psk"))
	k2, _ := deriveLxObfKey([]byte("psk"))
	if !bytes.Equal(k1, k2) {
		t.Fatal("unstable")
	}
}

func TestParsePadProfileAndGap(t *testing.T) {
	p, err := parseLxObfPadProfile("10:2,20:3")
	if err != nil || len(p) != 2 || p[0].pad != 10 {
		t.Fatal(err, p)
	}
	min, max, err := parseLxObfGapMs("5-25")
	if err != nil || min != 5 || max != 25 {
		t.Fatal(err, min, max)
	}
}

func TestEnvelopeLowEntropyAndIdlePersona(t *testing.T) {
	psk := []byte("low-entropy-key-material-xxxxxx")
	cfg := testCfg("quic-h3", 64)
	cfg.IdlePersona = "dns-idle"
	cfg.LowEntropy = true
	cfg.Strategy = "ascii"
	cfg.StartCover = 2
	cfg.CoverEveryMs = 1000
	m, err := newEnvelopeLxObf(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.StartCoverCount() != 2 {
		t.Fatal(m.StartCoverCount())
	}
	if m.CoverEvery() <= 0 {
		t.Fatal("cover every")
	}
	// keepalive-sized → idle persona path
	ka := bytes.Repeat([]byte{9}, MessageKeepaliveSize)
	sealed, err := m.Seal(ka)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := m.Open(sealed)
	if err != nil || !bytes.Equal(opened, ka) {
		t.Fatal(err, len(opened))
	}
}

func TestEnvelopeSealThroughputSynthetic(t *testing.T) {
	psk := []byte("bench-key-material-xxxxxxxxxxxxx")
	m, err := newEnvelopeLxObf(psk, testCfg("balanced", 64))
	if err != nil {
		t.Fatal(err)
	}
	wg := bytes.Repeat([]byte{3}, 1200)
	const N = 2000
	for i := 0; i < N; i++ {
		sealed, err := m.Seal(wg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Open(sealed); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFrameTLS13RoundTrip(t *testing.T) {
	psk := []byte("frame-tls-key-material-xxxxxxxx")
	cfg := testCfg("balanced", 48)
	cfg.Frame = "tls13"
	cli, err := newEnvelopeLxObf(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newEnvelopeLxObf(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	wg := bytes.Repeat([]byte{5}, 92)
	sealed, err := cli.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0] != 0x17 {
		t.Fatalf("want TLS content type, got %#x", sealed[0])
	}
	for _, classic := range []int{32, 64, 92, 148} {
		if len(sealed) == classic {
			t.Fatalf("framed size collapsed to classic %d", classic)
		}
	}
	opened, err := srv.Open(sealed)
	if err != nil || !bytes.Equal(opened, wg) {
		t.Fatal(err, len(opened))
	}
}

func TestFrameQUICShortRoundTrip(t *testing.T) {
	psk := []byte("frame-quic-key-material-xxxxxxx")
	cfg := testCfg("quic-h3", 40)
	cfg.Frame = "quic-short"
	cfg.FrameDCIDLen = 8
	m, err := newEnvelopeLxObf(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	wg := bytes.Repeat([]byte{6}, 148)
	sealed, err := m.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0]&0x40 == 0 || sealed[0]&0x80 != 0 {
		t.Fatalf("bad quic-short first byte %#x", sealed[0])
	}
	opened, err := m.Open(sealed)
	if err != nil || !bytes.Equal(opened, wg) {
		t.Fatal(err)
	}
}

func TestFrameDNSAndSTUNRoundTrip(t *testing.T) {
	psk := []byte("frame-dns-stun-key-material-xxx")
	for _, frame := range []string{"dns", "stun"} {
		cfg := testCfg("dns-idle", 32)
		cfg.Frame = frame
		m, err := newEnvelopeLxObf(psk, cfg)
		if err != nil {
			t.Fatal(frame, err)
		}
		wg := bytes.Repeat([]byte{7}, 64)
		sealed, err := m.Seal(wg)
		if err != nil {
			t.Fatal(frame, err)
		}
		opened, err := m.Open(sealed)
		if err != nil || !bytes.Equal(opened, wg) {
			t.Fatal(frame, err)
		}
	}
}

func TestQUICInitialDecoyShape(t *testing.T) {
	pkt, err := buildLxObfQUICInitialDecoy()
	if err != nil {
		t.Fatal(err)
	}
	if !isLxObfLikelyQUICInitial(pkt) {
		t.Fatal("not recognized as initial")
	}
	psk := []byte("decoy-open-key-material-xxxxxxx")
	m, err := newEnvelopeLxObf(psk, testCfg("balanced", 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Open(pkt)
	if !errors.Is(err, errLxObfCover) {
		t.Fatalf("want cover drop, got %v", err)
	}
}

func TestFrameCrossPersonaCompat(t *testing.T) {
	psk := []byte("cross-persona-frame-key-xxxxxxx")
	cliCfg := testCfg("quic-h3", 64)
	cliCfg.Frame = "tls13"
	srvCfg := testCfg("webrtc", 80)
	srvCfg.Frame = "tls13" // frame must match; persona may differ
	cli, err := newEnvelopeLxObf(psk, cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newEnvelopeLxObf(psk, srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	wg := bytes.Repeat([]byte{8}, 200)
	sealed, err := cli.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := srv.Open(sealed)
	if err != nil || !bytes.Equal(opened, wg) {
		t.Fatal(err)
	}
}

func TestAsymmetricFramesHubInterop(t *testing.T) {
	// Hub peer_relay reality: one device key, Seal frames may differ per endpoint.
	psk := []byte("hub-asymmetric-frame-key-xxxxx")
	mk := func(frame, persona string, pad int) *envelopeLxObf {
		cfg := testCfg(persona, pad)
		cfg.Frame = frame
		m, err := newEnvelopeLxObf(psk, cfg)
		if err != nil {
			t.Fatal(frame, err)
		}
		return m
	}
	a := mk("tls13", "quic-h3", 48)
	hub := mk("quic-short", "balanced", 64)
	b := mk("dns", "webrtc", 40)

	wg := bytes.Repeat([]byte{9}, 300)
	// A → hub
	sa, err := a.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	oa, err := hub.Open(sa)
	if err != nil || !bytes.Equal(oa, wg) {
		t.Fatal("A→hub", err)
	}
	// hub → A
	sh, err := hub.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	oh, err := a.Open(sh)
	if err != nil || !bytes.Equal(oh, wg) {
		t.Fatal("hub→A", err)
	}
	// B → hub → B
	sb, err := b.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	ob, err := hub.Open(sb)
	if err != nil || !bytes.Equal(ob, wg) {
		t.Fatal("B→hub", err)
	}
	ob2, err := b.Open(sh) // hub sealed with quic-short
	if err != nil || !bytes.Equal(ob2, wg) {
		t.Fatal("hub→B", err)
	}
}

func TestOverheadBoundsAndCachedDCID(t *testing.T) {
	psk := []byte("overhead-bounds-key-material-xx")
	cfg := testCfg("balanced", 64)
	cfg.Frame = "quic-short"
	cfg.FrameDCIDLen = 8
	m, err := newEnvelopeLxObf(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.dcid) != 8 {
		t.Fatalf("dcid not cached: %d", len(m.dcid))
	}
	d1 := m.frameDCID()
	d2 := m.frameDCID()
	if &d1[0] != &d2[0] {
		t.Fatal("dcid should be cached slice")
	}
	wg := bytes.Repeat([]byte{1}, 1000)
	const N = 200
	var sum int
	minOH, maxOH := 1<<30, 0
	frameOH := lxObfFrameOverhead("quic-short", 8)
	for i := 0; i < N; i++ {
		sealed, err := m.Seal(wg)
		if err != nil {
			t.Fatal(err)
		}
		oh := len(sealed) - len(wg)
		sum += oh
		if oh < minOH {
			minOH = oh
		}
		if oh > maxOH {
			maxOH = oh
		}
		// Fixed envelope 33 + frame + pad≤64 (+1 avoid classic)
		if oh < 33+frameOH || oh > 33+frameOH+65 {
			t.Fatalf("overhead %d out of bounds", oh)
		}
	}
	avg := float64(sum) / float64(N)
	t.Logf("quic-short overhead avg=%.1f min=%d max=%d (wg=%d)", avg, minOH, maxOH, len(wg))
}
