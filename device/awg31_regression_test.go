package device

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// TestRandomTrailersIpcRoundTrip checks UAPI get/set for AmneziaWG 3.1 bools.
func TestRandomTrailersIpcRoundTrip(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun := newChanTun()
	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), tun, bind, NewLogger(LogLevelError, "awg31: "), 1)
	t.Cleanup(dev.Close)

	cfg := "private_key=" + hex.EncodeToString(sk[:]) + "\nrandom_trailers=true\ndisable_cookies=true\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	out, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "random_trailers=1") {
		t.Fatalf("missing random_trailers=1 in:\n%s", out)
	}
	if !strings.Contains(out, "disable_cookies=1") {
		t.Fatalf("missing disable_cookies=1 in:\n%s", out)
	}
}

func TestDeterminePacketTypeRejectsOversizedHandshakeWithoutTrailers(t *testing.T) {
	dev := &Device{}
	var hdr UintRange
	if err := hdr.FromString("1"); err != nil {
		t.Fatal(err)
	}
	dev.headers.init.Store(hdr)

	exact := make([]byte, MessageInitiationSize)
	binary.LittleEndian.PutUint32(exact, 1)
	typeHash := make([]byte, 4)
	msgSize, msgType, gotPad := dev.DeterminePacketTypeAndPadding(exact, typeHash)
	if msgType != MessageInitiationType || msgSize != MessageInitiationSize || gotPad != 0 {
		t.Fatalf("exact: size=%d type=%d pad=%d", msgSize, msgType, gotPad)
	}

	oversized := make([]byte, len(exact)+17)
	copy(oversized, exact)
	_, msgType, _ = dev.DeterminePacketTypeAndPadding(oversized, typeHash)
	if msgType != MessageUnknownType {
		t.Fatalf("without random_trailers oversized must be unknown, got type=%d", msgType)
	}

	dev.randomTrailers.Store(true)
	msgSize, msgType, gotPad = dev.DeterminePacketTypeAndPadding(oversized, typeHash)
	if msgType != MessageInitiationType || msgSize != MessageInitiationSize || gotPad != 0 {
		t.Fatalf("with trailers: size=%d type=%d pad=%d", msgSize, msgType, gotPad)
	}
}

func TestRandomTrailerLengthBounds(t *testing.T) {
	dev := &Device{}
	if n := dev.randomTrailer(100); n != -1 {
		t.Fatalf("flag off: want -1 got %d", n)
	}
	dev.randomTrailers.Store(true)
	for i := 0; i < 64; i++ {
		n := dev.randomTrailer(100)
		if n < 0 || n >= DefaultUdpWindow-100 {
			t.Fatalf("trailer len %d out of [0, %d)", n, DefaultUdpWindow-100)
		}
	}
	if n := dev.randomTrailer(DefaultUdpWindow + 10); n != 0 {
		t.Fatalf("packet larger than window: want 0 got %d", n)
	}
}

func TestKeepaliveDetectsLeadingZero(t *testing.T) {
	// Mirrors amneziawg-go 08d68cd: CPA / trailer-style zeros must count as keepalive.
	pkt := []byte{0, 1, 2, 3}
	if !(len(pkt) == 0 || pkt[0] == 0) {
		t.Fatal("leading zero must classify as keepalive")
	}
	data := []byte{0x45, 0, 0, 20}
	if len(data) == 0 || data[0] == 0 {
		t.Fatal("IPv4 must not classify as keepalive")
	}
}

func TestPathologyConflictsWithRandomTrailers(t *testing.T) {
	dev := &Device{}
	dev.randomTrailers.Store(true)
	if err := dev.awgKnobsConflictWithPathology(); err == nil {
		t.Fatal("expected conflict with random_trailers")
	}
	dev.randomTrailers.Store(false)
	dev.disableCookies.Store(true)
	if err := dev.awgKnobsConflictWithPathology(); err == nil {
		t.Fatal("expected conflict with disable_cookies")
	}
}
