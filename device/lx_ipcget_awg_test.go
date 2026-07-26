/* SPDX-License-Identifier: MIT
 *
 * Pins the AWG get path: IpcGet must report every obfuscation parameter it
 * accepted, including i1..i5. The I-slots are emitted by an `i%d=` loop rather
 * than literal per-key sendf calls, which makes them easy to miss when auditing
 * introspection parity against amneziawg-go by grep alone.
 */

package device

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func TestIpcGetReportsAWGParams(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}

	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	set := strings.Join([]string{
		"private_key=" + hex.EncodeToString(sk[:]),
		"jc=4", "jmin=40", "jmax=70",
		"s1=15", "s2=20", "s3=25", "s4=30",
		"h1=1", "h2=2", "h3=3", "h4=100-200",
		"i1=<b 0xf6a1>", "i3=<r 8>", "i5=<t>",
		"",
	}, "\n")
	if err := dev.IpcSet(set); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}

	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	t.Logf("IpcGet:\n%s", got)

	for _, want := range []string{
		"jc=4", "jmin=40", "jmax=70",
		"s1=15", "s2=20", "s3=25", "s4=30",
		"h1=1", "h2=2", "h3=3", "h4=100-200",
		"i1=<b 0xf6a1>", "i3=<r 8>", "i5=<t>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("IpcGet missing %q", want)
		}
	}

	// Unset I-slots must stay absent, not surface as empty values.
	for _, absent := range []string{"i2=", "i4="} {
		if strings.Contains(got, absent) {
			t.Errorf("IpcGet reported unset %q", absent)
		}
	}
}
