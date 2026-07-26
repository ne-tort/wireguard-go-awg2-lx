package device

import (
	"testing"
	"time"
)

func TestBandwidthLimiterDisabledNoWait(t *testing.T) {
	var l BandwidthLimiter
	start := time.Now()
	l.Wait(1 << 20)
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("disabled limiter must not block")
	}
}

func TestBandwidthLimiterSetZeroDisables(t *testing.T) {
	var l BandwidthLimiter
	l.SetMbps(10)
	if !l.Enabled() || l.Mbps() != 10 {
		t.Fatalf("enabled=%v mbps=%d", l.Enabled(), l.Mbps())
	}
	l.SetMbps(0)
	if l.Enabled() || l.Mbps() != 0 {
		t.Fatalf("expected disabled, enabled=%v mbps=%d", l.Enabled(), l.Mbps())
	}
	start := time.Now()
	l.Wait(1 << 20)
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("zero mbps must not block")
	}
}

func TestBandwidthLimiterRate(t *testing.T) {
	var l BandwidthLimiter
	// 1 Mbps = 125000 B/s. Transfer ~62500 bytes → ~0.5s after burst drained.
	l.SetMbps(1)
	// Drain initial 1s burst.
	l.Wait(MbpsToBps)
	start := time.Now()
	l.Wait(MbpsToBps / 2)
	elapsed := time.Since(start)
	if elapsed < 350*time.Millisecond {
		t.Fatalf("expected ~500ms wait, got %v (too fast)", elapsed)
	}
	if elapsed > 900*time.Millisecond {
		t.Fatalf("expected ~500ms wait, got %v (too slow)", elapsed)
	}
}

func TestBandwidthPairDualCap(t *testing.T) {
	var peer, device BandwidthPair
	peer.SetUpMbps(100)
	device.SetUpMbps(1)
	// Effective upload ≤ 1 Mbps (device wins as stricter of both waits).
	n := MbpsToBps / 2
	device.WaitUp(MbpsToBps) // drain device burst
	peer.WaitUp(MbpsToBps)  // drain peer burst (large)
	start := time.Now()
	peer.WaitUp(n)
	device.WaitUp(n)
	elapsed := time.Since(start)
	if elapsed < 350*time.Millisecond {
		t.Fatalf("dual-cap should be limited by 1Mbps device, got %v", elapsed)
	}
}

func TestParseMbpsUAPI(t *testing.T) {
	v, err := parseMbpsUAPI("42")
	if err != nil || v != 42 {
		t.Fatalf("got %d %v", v, err)
	}
	if _, err := parseMbpsUAPI("-1"); err == nil {
		t.Fatal("expected error for negative")
	}
	if _, err := parseMbpsUAPI("x"); err == nil {
		t.Fatal("expected error for non-int")
	}
}
