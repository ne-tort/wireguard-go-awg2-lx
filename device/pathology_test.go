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

func TestIdentityPathologyRoundTrip(t *testing.T) {
	m := newIdentityPathology()
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

func TestParsePathologyUAPI(t *testing.T) {
	got, err := parsePathologyUAPI("true")
	if err != nil || !got {
		t.Fatal(err, got)
	}
	_, err = parsePathologyUAPI("nope")
	if err == nil {
		t.Fatal("expected err")
	}
}

func TestPathologyConflictsWithJunk(t *testing.T) {
	dev := &Device{}
	dev.junk.count.Store(3)
	if err := dev.awgKnobsConflictWithPathology(); err == nil {
		t.Fatal("expected conflict")
	}
}

func testCfg(persona string, pad int) pathologyRuntimeConfig {
	cfg := defaultPathologyRuntimeConfig()
	cfg.Persona = persona
	cfg.PadBudget = pad
	cfg.Preset = "custom"
	cfg.Cipher = pathologyCipherAEAD
	cfg.Frame = pathologyFrameNone
	cfg.Dialog = pathologyDialogOff
	cfg.Intensity = 3
	cfg.RotateSec = 0 // stable connection-scoped table in tests
	return cfg
}

func TestEnvelopeRoundTripAndLengthHide(t *testing.T) {
	psk := []byte("client-server-shared-secret-32b!!")
	cli, err := newEnvelopePathology(psk, testCfg("quic-h3", 64))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newEnvelopePathology(psk, testCfg("balanced", 96))
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
	m, err := newEnvelopePathology(psk, testCfg("dns-idle", 32))
	if err != nil {
		t.Fatal(err)
	}
	cover, err := m.SealCover()
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Open(cover)
	if !errors.Is(err, errPathologyCover) {
		t.Fatalf("want cover err, got %v", err)
	}
}

func TestEnvelopeCustomProfile(t *testing.T) {
	psk := []byte("profile-test-key-material-xxxxx")
	cfg := testCfg("custom", 80)
	cfg.PadProfile = []pathologyPadMode{{pad: 10, weight: 1}, {pad: 20, weight: 1}}
	cfg.Cipher = pathologyCipherAEAD
	cfg.Frame = pathologyFrameNone
	m, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		sealed, err := m.Seal(bytes.Repeat([]byte{1}, 64))
		if err != nil {
			t.Fatal(err)
		}
		pad := len(sealed) - (64 + m.fixedOH)
		if pad != 10 && pad != 20 && pad != 11 && pad != 21 {
			if pad < 10 || pad > 22 {
				t.Fatalf("unexpected pad %d", pad)
			}
		}
	}
}

func TestEnvelopeWrongKey(t *testing.T) {
	cfg := testCfg("balanced", 32)
	cfg.Cipher = pathologyCipherAEAD // only aead authenticates outer envelope
	a, err := newEnvelopePathology([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newEnvelopePathology([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), cfg)
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
	m, err := newEnvelopePathology([]byte("replay-test-key-material-xxxxxx"), testCfg("dns-idle", 16))
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
	k1, _ := derivePathologyKey([]byte("psk"))
	k2, _ := derivePathologyKey([]byte("psk"))
	if !bytes.Equal(k1, k2) {
		t.Fatal("unstable")
	}
}

func TestParsePadProfileAndGap(t *testing.T) {
	p, err := parsePathologyPadProfile("10:2,20:3")
	if err != nil || len(p) != 2 || p[0].pad != 10 {
		t.Fatal(err, p)
	}
	min, max, err := parsePathologyGapMs("5-25")
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
	m, err := newEnvelopePathology(psk, cfg)
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
	m, err := newEnvelopePathology(psk, testCfg("balanced", 64))
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
	cli, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newEnvelopePathology(psk, cfg)
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
	m, err := newEnvelopePathology(psk, cfg)
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
		m, err := newEnvelopePathology(psk, cfg)
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
	pkt, err := buildPathologyQUICInitialDecoy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !isPathologyLikelyQUICInitial(pkt) {
		t.Fatal("not recognized as initial")
	}
	psk := []byte("decoy-open-key-material-xxxxxxx")
	m, err := newEnvelopePathology(psk, testCfg("balanced", 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Open(pkt)
	if !errors.Is(err, errPathologyCover) {
		t.Fatalf("want cover drop, got %v", err)
	}
}

func TestFrameCrossPersonaCompat(t *testing.T) {
	psk := []byte("cross-persona-frame-key-xxxxxxx")
	cliCfg := testCfg("quic-h3", 64)
	cliCfg.Frame = "tls13"
	srvCfg := testCfg("webrtc", 80)
	srvCfg.Frame = "tls13" // frame must match; persona may differ
	cli, err := newEnvelopePathology(psk, cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newEnvelopePathology(psk, srvCfg)
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
	mk := func(frame, persona string, pad int) *envelopePathology {
		cfg := testCfg(persona, pad)
		cfg.Frame = frame
		m, err := newEnvelopePathology(psk, cfg)
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
	m, err := newEnvelopePathology(psk, cfg)
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
	frameOH := pathologyFrameOverhead("quic-short", 8)
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
		// Fixed envelope (cipher) + frame + pad≤64 (+1 avoid classic)
		if oh < m.fixedOH+frameOH || oh > m.fixedOH+frameOH+65 {
			t.Fatalf("overhead %d out of bounds (fixed=%d frame=%d)", oh, m.fixedOH, frameOH)
		}
	}
	avg := float64(sum) / float64(N)
	t.Logf("quic-short overhead avg=%.1f min=%d max=%d (wg=%d)", avg, minOH, maxOH, len(wg))
}

func TestStreamHeaderScrambleOnly(t *testing.T) {
	psk := []byte("stream-header-scramble-key-xxxx")
	cfg := testCfg("balanced", 16)
	cfg.Cipher = "stream"
	cfg.Frame = pathologyFrameNone
	m, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	wg := bytes.Repeat([]byte{0x5a}, 200)
	sealed, err := m.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	// After ver|pad|nonce, first 16 body bytes are scrambled; WG tail untouched.
	const scramble = 16
	pad := int(sealed[1])
	body := sealed[:len(sealed)-pad]
	ct := body[pathologyHdrSize+pathologyNonceSize:]
	if !bytes.Equal(ct[scramble:], wg[scramble-pathologyMetaSize:]) {
		t.Fatal("stream should leave WG tail untouched")
	}
	opened, err := m.Open(sealed)
	if err != nil || !bytes.Equal(opened, wg) {
		t.Fatal(err)
	}
}

func TestCipherTiersRoundTrip(t *testing.T) {
	psk := []byte("cipher-tier-shared-secret-xxxx")
	wg := bytes.Repeat([]byte{0xab}, 200)
	for _, cipher := range []string{"aead", "stream", "none"} {
		cfg := testCfg("balanced", 48)
		cfg.Cipher = cipher
		if cipher == "none" {
			cfg.Frame = "tls13"
		}
		cli, err := newEnvelopePathology(psk, cfg)
		if err != nil {
			t.Fatal(cipher, err)
		}
		srv, err := newEnvelopePathology(psk, cfg)
		if err != nil {
			t.Fatal(cipher, err)
		}
		sealed, err := cli.Seal(wg)
		if err != nil {
			t.Fatal(cipher, err)
		}
		if len(sealed) == len(wg) {
			t.Fatalf("%s: no length hide", cipher)
		}
		opened, err := srv.Open(sealed)
		if err != nil {
			t.Fatal(cipher, err)
		}
		if !bytes.Equal(opened, wg) {
			t.Fatalf("%s: mismatch", cipher)
		}
		// Open accepts any cipher version from the same PSK (asymmetric Seal OK).
		other := testCfg("balanced", 48)
		switch cipher {
		case "aead":
			other.Cipher = "stream"
		default:
			other.Cipher = "aead"
		}
		peer, err := newEnvelopePathology(psk, other)
		if err != nil {
			t.Fatal(err)
		}
		out, err := peer.Open(sealed)
		if err != nil || !bytes.Equal(out, wg) {
			t.Fatalf("%s: multi-cipher open failed: %v", cipher, err)
		}
	}
}

func TestPresetFastDefaults(t *testing.T) {
	psk := []byte("preset-fast-key-material-xxxxxx")
	cfg := defaultPathologyRuntimeConfig()
	cfg.Persona = "quic-h3"
	cfg.PadBudget = 64
	cfg.Preset = "fast"
	m, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.cipher != pathologyCipherNone || m.cfg.Frame != pathologyFrameTLS13 {
		t.Fatalf("preset fast => cipher=%s frame=%s", m.cipher, m.cfg.Frame)
	}
	if m.cfg.PadBudget != 24 {
		t.Fatalf("preset fast should shrink default pad_budget, got %d", m.cfg.PadBudget)
	}
	wg := bytes.Repeat([]byte{9}, 64)
	sealed, err := m.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := m.Open(sealed)
	if err != nil || !bytes.Equal(opened, wg) {
		t.Fatal(err)
	}
}

func TestEpochStableAndPadQuanta(t *testing.T) {
	psk := []byte("epoch-stable-key-material-xxxxx")
	cfg := testCfg("balanced", 64)
	cfg.Cipher = pathologyCipherStream
	cfg.Frame = pathologyFrameNone
	cfg.RotateSec = 0
	m, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t1 := m.ensureEpoch()
	t2 := m.ensureEpoch()
	if t1.epoch != t2.epoch || t1.padBudget != t2.padBudget {
		t.Fatal("epoch table unstable within connection")
	}
	if len(t1.pads) == 0 {
		t.Fatal("empty pad quanta")
	}
	wg := bytes.Repeat([]byte{1}, 100)
	s1, _ := m.Seal(wg)
	// Same counter path: next seal uses next ctr — pads may differ; Open must work.
	s2, _ := m.Seal(wg)
	for _, s := range [][]byte{s1, s2} {
		out, err := m.Open(s)
		if err != nil || !bytes.Equal(out, wg) {
			t.Fatal(err)
		}
	}
	// Same PSK+epoch → same morph seed
	seed1, _ := derivePathologyEpoch(psk, 42)
	seed2, _ := derivePathologyEpoch(psk, 42)
	seed3, _ := derivePathologyEpoch(psk, 43)
	if !bytes.Equal(seed1, seed2) {
		t.Fatal("epoch derive unstable")
	}
	if bytes.Equal(seed1, seed3) {
		t.Fatal("different epochs should differ")
	}
}

func TestPresetBalancedDefaults(t *testing.T) {
	psk := []byte("preset-balanced-key-material-xx")
	cfg := defaultPathologyRuntimeConfig()
	cfg.Preset = "balanced"
	m, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.cipher != pathologyCipherStream || m.cfg.Frame != pathologyFrameTLS13 {
		t.Fatalf("balanced => cipher=%s frame=%s", m.cipher, m.cfg.Frame)
	}
}

func TestFrameAutoEpoch(t *testing.T) {
	psk := []byte("frame-auto-epoch-key-material-x")
	cfg := testCfg("quic-h3", 32)
	cfg.Cipher = pathologyCipherStream
	cfg.Frame = pathologyFrameAuto
	cfg.RotateSec = 0
	cli, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	wg := bytes.Repeat([]byte{3}, 80)
	sealed, err := cli.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := srv.Open(sealed)
	if err != nil || !bytes.Equal(opened, wg) {
		t.Fatal(err)
	}
	fr := cli.sealFrame()
	if fr != pathologyFrameTLS13 && fr != pathologyFrameQUICShort {
		t.Fatalf("auto frame got %s", fr)
	}
}

func TestIntensityAndMode(t *testing.T) {
	psk := []byte("intensity-mode-key-material-xxxx")
	cfg := defaultPathologyRuntimeConfig()
	cfg.Preset = "custom"
	cfg.Cipher = pathologyCipherStream
	cfg.Mode = "quic"
	cfg.Intensity = 1
	cfg.RotateSec = 0
	m, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.cfg.Persona != "quic-h3" {
		t.Fatalf("mode quic => persona %s", m.cfg.Persona)
	}
	if m.cfg.Intensity != 1 {
		t.Fatalf("intensity=%d", m.cfg.Intensity)
	}
	tab := m.ensureEpoch()
	if tab.frame != pathologyFrameTLS13 {
		t.Fatalf("intensity=1 auto frames should be tls13-only, got %s", tab.frame)
	}
	if tab.padBudget > 30 {
		t.Fatalf("intensity=1 should shrink pad budget, got %d", tab.padBudget)
	}

	cfg5 := defaultPathologyRuntimeConfig()
	cfg5.Preset = "custom"
	cfg5.Cipher = pathologyCipherStream
	cfg5.Frame = pathologyFrameAuto
	cfg5.Intensity = 5
	cfg5.RotateSec = 0
	m5, err := newEnvelopePathology(psk, cfg5)
	if err != nil {
		t.Fatal(err)
	}
	fr := m5.ensureEpoch().frame
	switch fr {
	case pathologyFrameTLS13, pathologyFrameQUICShort, pathologyFrameDNS:
	default:
		t.Fatalf("intensity=5 unexpected auto frame %s", fr)
	}

	wg := bytes.Repeat([]byte{4}, 64)
	sealed, err := m.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := m.Open(sealed)
	if err != nil || !bytes.Equal(opened, wg) {
		t.Fatal(err)
	}
}

func TestBalanceStrategyCoerced(t *testing.T) {
	s, err := normalizePathologyStrategy("balance")
	if err != nil || s != "random" {
		t.Fatalf("balance should coerce to random, got %q %v", s, err)
	}
}

func TestMultiCipherOpenAsymmetric(t *testing.T) {
	psk := []byte("multi-cipher-open-key-materialxx")
	mk := func(cipher string) *envelopePathology {
		cfg := testCfg("balanced", 32)
		cfg.Cipher = cipher
		cfg.Frame = pathologyFrameTLS13
		m, err := newEnvelopePathology(psk, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	cli := mk(pathologyCipherNone)
	srv := mk(pathologyCipherAEAD)
	wg := bytes.Repeat([]byte{9}, 64)
	sealed, err := cli.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := srv.Open(sealed)
	if err != nil || !bytes.Equal(out, wg) {
		t.Fatalf("asym cipher open: %v", err)
	}
	sealed2, err := srv.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	out, err = cli.Open(sealed2)
	if err != nil || !bytes.Equal(out, wg) {
		t.Fatalf("reverse asym open: %v", err)
	}
}

func TestDialogDNSSTUNRoundTrip(t *testing.T) {
	psk := []byte("dialog-dns-stun-key-materialxxx")
	cfg := testCfg("dns-idle", 32)
	cfg.Cipher = pathologyCipherStream
	cfg.Mode = "dns"
	cfg.Dialog = pathologyDialogDNS
	cfg.Frame = pathologyFrameTLS13
	cli, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	steps := cli.BuildStartDialog()
	if len(steps) != 1 || !looksLikePathologyDNSQuery(steps[0].Packet) {
		t.Fatalf("dns dialog steps=%d", len(steps))
	}
	reply, ok := srv.MaybeDialogReply(steps[0].Packet)
	if !ok || !looksLikePathologyDNSResponse(reply) {
		t.Fatal("dns reply missing")
	}
	if reply[0] != steps[0].Packet[0] || reply[1] != steps[0].Packet[1] {
		t.Fatal("dns ID mismatch")
	}
	if _, err := cli.Open(reply); !errors.Is(err, errPathologyCover) {
		t.Fatalf("dns resp open want cover, got %v", err)
	}

	cfg.Mode = "stun"
	cfg.Dialog = pathologyDialogSTUN
	cli2, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv2, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	steps = cli2.BuildStartDialog()
	if len(steps) != 1 || !looksLikePathologySTUNBindingReq(steps[0].Packet) {
		t.Fatal("stun dialog")
	}
	reply, ok = srv2.MaybeDialogReply(steps[0].Packet)
	if !ok || !looksLikePathologySTUNBindingSuccess(reply) {
		t.Fatal("stun reply")
	}
	if !bytes.Equal(reply[8:20], steps[0].Packet[8:20]) {
		t.Fatal("stun TXID mismatch")
	}
}

func TestAutoProfileFills(t *testing.T) {
	psk := []byte("auto-profile-fill-key-materialx")
	cfg := defaultPathologyRuntimeConfig()
	cfg.Auto = true
	cfg.Preset = ""
	cfg.Intensity = 0
	cfg.RotateSec = pathologyDefaultRotateSec
	m, err := newEnvelopePathology(psk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.cfg.Mode == "" {
		t.Fatal("auto should set mode")
	}
	if m.cfg.Intensity < 2 || m.cfg.Intensity > 4 {
		t.Fatalf("auto intensity=%d", m.cfg.Intensity)
	}
	if m.cipher == "" {
		t.Fatal("auto cipher")
	}
	wg := bytes.Repeat([]byte{1}, 48)
	sealed, err := m.Seal(wg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Open(sealed)
	if err != nil || !bytes.Equal(out, wg) {
		t.Fatal(err)
	}
}

func TestAutoStableSameKeySameHour(t *testing.T) {
	psk := []byte("auto-stable-seed-key-materialxxx")
	pick := func() (mode, cipher, frame string, intensity int) {
		cfg := defaultPathologyRuntimeConfig()
		cfg.Auto = true
		m, err := newEnvelopePathology(psk, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return m.cfg.Mode, m.cipher, m.cfg.Frame, m.cfg.Intensity
	}
	m1, c1, f1, i1 := pick()
	for n := 0; n < 5; n++ {
		m, c, f, i := pick()
		if m != m1 || c != c1 || f != f1 || i != i1 {
			t.Fatalf("auto unstable: first=(%s %s %s %d) got=(%s %s %s %d)", m1, c1, f1, i1, m, c, f, i)
		}
	}
}

func TestAutoCatalogProfilesSealOpen(t *testing.T) {
	psk := []byte("auto-catalog-roundtrip-keyxxxxxx")
	for i, p := range pathologyAutoCatalog {
		cfg := defaultPathologyRuntimeConfig()
		cfg.Mode = p.mode
		cfg.Cipher = p.cipher
		cfg.Frame = p.frame
		cfg.Dialog = p.dialog
		cfg.Intensity = p.intensity
		cfg.RotateSec = p.rotateSec
		if p.startDecoy != "" {
			cfg.StartDecoy = p.startDecoy
		}
		cfg.Preset = pathologyPresetCustom
		m, err := newEnvelopePathology(psk, cfg)
		if err != nil {
			t.Fatalf("profile[%d] new: %v", i, err)
		}
		wg := bytes.Repeat([]byte{byte(i + 1)}, 80)
		sealed, err := m.Seal(wg)
		if err != nil {
			t.Fatalf("profile[%d] seal: %v", i, err)
		}
		out, err := m.Open(sealed)
		if err != nil || !bytes.Equal(out, wg) {
			t.Fatalf("profile[%d] open: %v", i, err)
		}
	}
}


// forceEpochForTest pins a connection-scoped epoch id (rotate_sec=0 path).
func (e *envelopePathology) forceEpochForTest(id uint64) {
	e.epoch.mu.Lock()
	defer e.epoch.mu.Unlock()
	e.epoch.rotate = 0
	e.epoch.connEpo = id
	_ = e.refreshEpochLocked(false)
}

func TestKeyOnlyResolvedDefaults(t *testing.T) {
	psk := []byte("key-only-defaults-material-xxxxx")
	m, err := newEnvelopePathology(psk, defaultPathologyRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if m.cipher != pathologyCipherStream {
		t.Fatalf("default cipher=%s want stream", m.cipher)
	}
	if m.cfg.Frame != pathologyFrameTLS13 {
		t.Fatalf("default frame=%s want tls13", m.cfg.Frame)
	}
	if m.cfg.Intensity != 3 {
		t.Fatalf("default intensity=%d", m.cfg.Intensity)
	}
	if m.cfg.RotateSec != pathologyDefaultRotateSec {
		t.Fatalf("default rotate_sec=%d", m.cfg.RotateSec)
	}
	if m.cfg.Persona != "balanced" {
		t.Fatalf("default persona=%s", m.cfg.Persona)
	}
	if m.cfg.PadBudget != 64 || m.cfg.Strategy != "auto" || m.cfg.IdlePersona != "dns-idle" {
		t.Fatalf("unexpected defaults %+v", m.cfg)
	}
	if m.cfg.StartDecoy != "none" || m.cfg.StartCover != 0 || m.cfg.CoverEveryMs != 0 {
		t.Fatalf("unexpected start/cover defaults %+v", m.cfg)
	}
	if m.cfg.Dialog != pathologyDialogAuto {
		t.Fatalf("default dialog=%s", m.cfg.Dialog)
	}
}

func TestEpochRotationDoesNotBreakPeers(t *testing.T) {
	psk := []byte("epoch-rotate-survive-key-xxxxxx")
	mk := func() *envelopePathology {
		cfg := defaultPathologyRuntimeConfig()
		cfg.Preset = "custom"
		cfg.Cipher = pathologyCipherStream
		cfg.Frame = pathologyFrameAuto
		cfg.Intensity = 5 // tls13|quic-short|dns — maximizes Open autodetect stress
		cfg.RotateSec = 0
		cfg.PadBudget = 48
		m, err := newEnvelopePathology(psk, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	cli, srv := mk(), mk()
	wg := bytes.Repeat([]byte{0xab}, 96)

	var sawFrames = map[string]bool{}
	for epoch := uint64(1); epoch <= 32; epoch++ {
		// Deliberate clock skew: peers never share the same Seal epoch.
		cli.forceEpochForTest(epoch)
		srv.forceEpochForTest(epoch + 1000)

		c2s, err := cli.Seal(wg)
		if err != nil {
			t.Fatalf("cli seal epoch %d: %v", epoch, err)
		}
		sawFrames[cli.ensureEpoch().frame] = true
		out, err := srv.Open(c2s)
		if err != nil || !bytes.Equal(out, wg) {
			t.Fatalf("srv open epoch skew %d (cli frame=%s): %v", epoch, cli.ensureEpoch().frame, err)
		}

		s2c, err := srv.Seal(wg)
		if err != nil {
			t.Fatalf("srv seal: %v", err)
		}
		out, err = cli.Open(s2c)
		if err != nil || !bytes.Equal(out, wg) {
			t.Fatalf("cli open after srv rotate: %v", err)
		}

		// Mid-session rotate on one side only; next packet must still open.
		cli.forceEpochForTest(epoch + 50)
		c2s, err = cli.Seal(wg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = srv.Open(c2s); err != nil {
			t.Fatalf("open after mid-session rotate: %v (frame=%s)", err, cli.ensureEpoch().frame)
		}
	}
	// With intensity=5 and 32 epochs we expect more than one frame type eventually.
	if len(sawFrames) < 2 {
		t.Logf("warning: only saw frames %v (RNG of seed may cluster; not fatal)", sawFrames)
	}
}

func TestModeSugarIsStructuralPrefixOnly(t *testing.T) {
	minInt := func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}
	psk := []byte("mode-sugar-structural-only-xxx")
	wg := bytes.Repeat([]byte{7}, 80)

	cases := []struct {
		mode   string
		check  func(t *testing.T, sealed []byte)
		frame  string // expected cfg.Frame after resolve (not auto)
	}{
		{"tls", func(t *testing.T, s []byte) {
			if len(s) < 5 || s[0] != 0x17 || s[1] != 0x03 || s[2] != 0x03 {
				t.Fatalf("tls mode: want TLS app-data record hdr, got %x", s[:minInt(8, len(s))])
			}
			// Not a TLS handshake / no request-response — just record + envelope.
			body := s[5:]
			if len(body) == 0 || !isPathologyEnvelopeVersion(body[0]) {
				t.Fatal("tls: envelope must follow hdr immediately (no TLS handshake)")
			}
		}, pathologyFrameTLS13},
		{"dns", func(t *testing.T, s []byte) {
			if len(s) < 12 {
				t.Fatal("dns short")
			}
			// Legend header only: QDCOUNT=1, but no QNAME — envelope at offset 12.
			if s[4] != 0 || s[5] != 1 {
				t.Fatalf("dns QDCOUNT want 1, got %x", s[4:6])
			}
			if isPathologyEnvelopeVersion(s[0]) {
				t.Fatal("dns should not start with envelope ver")
			}
			if !isPathologyEnvelopeVersion(s[12]) {
				t.Fatal("dns: no QNAME — envelope must start at +12 (not a real DNS query)")
			}
		}, pathologyFrameDNS},
		{"stun", func(t *testing.T, s []byte) {
			if len(s) < 20 || s[4] != 0x21 || s[5] != 0x12 || s[6] != 0xa4 || s[7] != 0x42 {
				t.Fatalf("stun magic missing: %x", s[:minInt(20, len(s))])
			}
			if !isPathologyEnvelopeVersion(s[20]) {
				t.Fatal("stun: no attributes — envelope at +20 (not Binding req/resp dialog)")
			}
		}, pathologyFrameSTUN},
		{"quic", func(t *testing.T, s []byte) {
			// mode=quic → frame=auto; first byte is either TLS 0x17 or QUIC short (fixed bit).
			if len(s) < 2 {
				t.Fatal("short")
			}
			if s[0] == 0x17 {
				if !isPathologyEnvelopeVersion(s[5]) {
					t.Fatal("quic/auto tls path: no handshake body")
				}
				return
			}
			if s[0]&0x80 != 0 {
				t.Fatal("quic mode mid-flow must not be long-header (Initial is start_decoy only)")
			}
			if s[0]&0x40 == 0 {
				t.Fatal("quic-short fixed bit")
			}
		}, pathologyFrameAuto},
		{"webrtc", func(t *testing.T, s []byte) {
			// webrtc → quic-short structural only
			if s[0]&0x80 != 0 || s[0]&0x40 == 0 {
				t.Fatalf("webrtc want quic-short shape, got %02x", s[0])
			}
		}, pathologyFrameQUICShort},
	}

	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := defaultPathologyRuntimeConfig()
			cfg.Preset = "custom"
			cfg.Cipher = pathologyCipherStream
			cfg.Mode = tc.mode
			cfg.RotateSec = 0
			cfg.Intensity = 3
			cfg.StartDecoy = "none"
			cfg.StartCover = 0
			m, err := newEnvelopePathology(psk, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if m.cfg.Frame != tc.frame {
				t.Fatalf("frame=%s want %s", m.cfg.Frame, tc.frame)
			}
			sealed, err := m.Seal(wg)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, sealed)
			out, err := m.Open(sealed)
			if err != nil || !bytes.Equal(out, wg) {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkPathologySealOpen(b *testing.B) {
	psk := []byte("bench-pathology-key-material-xxxxx")
	wg := bytes.Repeat([]byte{7}, 1200)
	for _, cipher := range []string{"aead", "stream", "none"} {
		cfg := testCfg("balanced", 32)
		cfg.Cipher = cipher
		if cipher == "none" {
			cfg.Frame = "tls13"
		}
		m, err := newEnvelopePathology(psk, cfg)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(cipher, func(b *testing.B) {
			b.SetBytes(int64(len(wg)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sealed, err := m.Seal(wg)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := m.Open(sealed); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
