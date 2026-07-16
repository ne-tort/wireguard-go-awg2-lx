/* SPDX-License-Identifier: MIT
 *
 * Guards around AWG obfuscation config values: these tests pin the
 * crash-on-config-value fixes (swapped jmin/jmax, out-of-range obfuscator
 * lengths, full-range magic headers).
 */

package device

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestParseObfLen(t *testing.T) {
	cases := []struct {
		val     string
		want    int
		wantErr bool
	}{
		{"0", 0, false},
		{"100", 100, false},
		{fmt.Sprintf("%d", MaxMessageSize), MaxMessageSize, false},
		{"-1", 0, true}, // would panic slice bounds in Obfuscate
		{fmt.Sprintf("%d", MaxMessageSize+1), 0, true}, // would OOM the handshake make
		{"2000000000", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := parseObfLen(c.val)
		if c.wantErr != (err != nil) {
			t.Errorf("parseObfLen(%q): err = %v, wantErr = %v", c.val, err, c.wantErr)
		}
		if err == nil && got != c.want {
			t.Errorf("parseObfLen(%q) = %d, want %d", c.val, got, c.want)
		}
	}
}

func TestMagicHeaderGenerateFullRange(t *testing.T) {
	// end-start+1 computed in uint32 wraps to 0 for the full range and
	// panics rand.Int; the fix widens to int64 before the arithmetic.
	h := &magicHeader{start: 0, end: ^uint32(0)}
	for i := 0; i < 8; i++ {
		v := h.Generate()
		if !h.Validate(v) {
			t.Fatalf("generated value %d outside range", v)
		}
	}
}

// TestJunkSwappedBounds brings up a device pair whose junk config has
// jmin > jmax (passes per-field UAPI validation); without the swap guard
// the first handshake panics rand.Int with a non-positive bound.
func TestJunkSwappedBounds(t *testing.T) {
	skA, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey A: %v", err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey B: %v", err)
	}
	pkA := skA.publicKey()
	pkB := skB.publicKey()

	bindA, bindB := newChanBindPair()
	tunA := newChanTun()
	tunB := newChanTun()

	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	// jmin deliberately greater than jmax: each field alone is valid.
	junk := "jc=2\njmin=100\njmax=50\n"
	cfgA := fmt.Sprintf(
		"private_key=%s\n%sreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
		hex.EncodeToString(skA[:]), junk, hex.EncodeToString(pkB[:]), testIPB)
	cfgB := fmt.Sprintf(
		"private_key=%s\n%sreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
		hex.EncodeToString(skB[:]), junk, hex.EncodeToString(pkA[:]), testIPA)

	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatalf("IpcSet A: %v", err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatalf("IpcSet B: %v", err)
	}

	if err := devA.Up(); err != nil {
		t.Fatalf("Up A: %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("Up B: %v", err)
	}

	// Drive a packet end-to-end: the handshake (junk packets included)
	// must complete without panicking the process.
	pkt := buildIPv4Packet(testIPA, testIPB, 28)
	devA.InputPacket(testIPB.AsSlice(), [][]byte{pkt})
	awaitPacket(t, tunB, pkt, func() {
		devA.InputPacket(testIPB.AsSlice(), [][]byte{pkt})
	})
}
