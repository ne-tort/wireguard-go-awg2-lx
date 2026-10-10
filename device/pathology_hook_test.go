/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Leadaxe / sing-box-lx. All Rights Reserved.
 *
 * lx: SPEC 059 / D28 wave B — device hook tests for the injected morpher.
 * The morpher implementation (envelope, appearance, dialogs) is fork-side
 * (sing-box transport/wireguard); these tests drive the hook surface with a
 * fake and keep the wave-A device-level guarantees: the start prelude never
 * blocks the device send path, AWG↔pathology exclusion holds at injection,
 * and nil disables the hook (genuine passthrough).
 */

package device

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"sync/atomic"
)

// fakePathologyMorpher is a minimal PathologyCoverMorpher: Seal tags packets
// with a 0xEE prefix so tests can tell sealed bytes from raw ones.
type fakePathologyMorpher struct {
	sealCalls   atomic.Int64
	coverCalls  atomic.Int64
	steps       []PathologyDialogStep
	gapMin      time.Duration
	gapMax      time.Duration
	coverEvery  time.Duration
	startCover  int
	startDecoy  string
	dialogReply []byte
}

func (f *fakePathologyMorpher) Seal(packet []byte) ([]byte, error) {
	f.sealCalls.Add(1)
	out := make([]byte, 0, len(packet)+1)
	out = append(out, 0xEE)
	return append(out, packet...), nil
}

func (f *fakePathologyMorpher) Open(packet []byte) ([]byte, error) {
	if len(packet) > 0 && packet[0] == 0xEE {
		return packet[1:], nil
	}
	return nil, ErrPathologyCover
}

func (f *fakePathologyMorpher) SealCover() ([]byte, error) {
	f.coverCalls.Add(1)
	return []byte{0xC0, 0xFF, 0xEE}, nil
}

func (f *fakePathologyMorpher) StartCoverCount() int { return f.startCover }

func (f *fakePathologyMorpher) StartGap() (min, max time.Duration) {
	return f.gapMin, f.gapMax
}

func (f *fakePathologyMorpher) CoverEvery() time.Duration { return f.coverEvery }

func (f *fakePathologyMorpher) StartDecoyMode() string { return f.startDecoy }

func (f *fakePathologyMorpher) BuildStartDecoy() ([]byte, error) {
	return bytes.Repeat([]byte{0xC0}, 1200), nil
}

func (f *fakePathologyMorpher) BuildStartDialog() []PathologyDialogStep { return f.steps }

func (f *fakePathologyMorpher) MaybeDialogReply(packet []byte) ([]byte, bool) {
	if f.dialogReply != nil && bytes.Equal(packet, f.dialogReply) {
		return []byte{0xD1}, true
	}
	return nil, false
}

func stunLegend() []byte {
	out := make([]byte, 20)
	binary.BigEndian.PutUint16(out[0:2], 0x0001)
	out[4], out[5], out[6], out[7] = 0x21, 0x12, 0xa4, 0x42
	return out
}

func TestPathologyConflictsWithJunk(t *testing.T) {
	dev := &Device{}
	dev.junk.count.Store(3)
	if err := dev.awgKnobsConflictWithPathology(); err == nil {
		t.Fatal("expected conflict")
	}
}

// D28 wave B: injection is the enable path, and it must refuse to run next to
// wire-changing AmneziaWG knobs (mutual exclusion preserved from wave A).
func TestSetPathologyMorpherAWGExclusion(t *testing.T) {
	dev := &Device{}
	dev.junk.count.Store(3)
	if err := dev.SetPathologyMorpher(&fakePathologyMorpher{}); err == nil {
		t.Fatal("SetPathologyMorpher must reject while AWG junk is active")
	}
	if dev.pathologyEnabled() {
		t.Fatal("rejected injection must not enable pathology")
	}

	clean := &Device{}
	if err := clean.SetPathologyMorpher(&fakePathologyMorpher{}); err != nil {
		t.Fatal(err)
	}
	if !clean.pathologyEnabled() {
		t.Fatal("injection must enable pathology")
	}
	// And the other direction: AWG knobs are refused while pathology is on.
	if err := clean.errIfPathologyBlocksAWG("jc"); err == nil {
		t.Fatal("expected AWG to be blocked while pathology is enabled")
	}
}

// Keyless / disabled: nil morpher turns the hook into a genuine passthrough.
func TestSetPathologyMorpherNilDisables(t *testing.T) {
	dev := &Device{}
	if err := dev.SetPathologyMorpher(&fakePathologyMorpher{}); err != nil {
		t.Fatal(err)
	}
	if err := dev.SetPathologyMorpher(nil); err != nil {
		t.Fatal(err)
	}
	if dev.pathologyEnabled() {
		t.Fatal("nil morpher must disable pathology")
	}
	in := []byte{1, 2, 3, 4, 5}
	out, err := dev.pathologySeal(in)
	if err != nil || !bytes.Equal(out, in) {
		t.Fatalf("disabled seal must pass through: %v", err)
	}
	out, err = dev.pathologyOpen(in)
	if err != nil || !bytes.Equal(out, in) {
		t.Fatalf("disabled open must pass through: %v", err)
	}
}

// N5-4 (wave A, moved): with a dialog configured, SendHandshakeInitiation must
// return immediately — the RTT-scale sleeps run on a dedicated goroutine, so
// neither RoutineReadFromTUN nor RoutineSequentialReceiver (both reach it via
// SendStagedPackets) ever stalls the device. Legend order is preserved: the
// dialog datagram hits the wire before the (sealed) initiation.
func TestStartPreludeNotOnDeviceSendPath(t *testing.T) {
	skA, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pkB := skB.publicKey()

	// Single-device capture bind: nothing consumes tx, so the test observes
	// the exact wire order (no race with a peer receive loop).
	tx := make(chan []byte, 64)
	bind := &chanBind{rx: make(chan []byte), tx: tx, source: 1, target: 2}
	tunDev := newChanTun()
	dev := NewDevice(context.Background(), tunDev, bind, NewLogger(LogLevelError, "preludeA: "), 1)
	t.Cleanup(dev.Close)
	ipc := fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
		hex.EncodeToString(skA[:]), hex.EncodeToString(pkB[:]), testIPB)
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	legend := stunLegend()
	m := &fakePathologyMorpher{
		steps: []PathologyDialogStep{{Packet: legend, WaitMs: 200}},
	}
	if err := dev.SetPathologyMorpher(m); err != nil {
		t.Fatal(err)
	}

	dev.peers.RLock()
	peer := dev.peers.keyMap[pkB]
	dev.peers.RUnlock()
	if peer == nil {
		t.Fatal("peer missing")
	}
	// Drain any setup-time datagram and clear the rekey-min-timeout guard so
	// the measured call is the one that runs the prelude.
drain:
	for {
		select {
		case <-tx:
		case <-time.After(200 * time.Millisecond):
			break drain
		}
	}
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Time{}
	peer.handshake.mutex.Unlock()

	start := time.Now()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("SendHandshakeInitiation blocked %v on the dialog prelude (want <100ms, wait=200ms)", elapsed)
	}

	recv := func(timeout time.Duration) ([]byte, time.Time) {
		select {
		case pkt := <-tx:
			return pkt, time.Now()
		case <-time.After(timeout):
			t.Fatal("timeout waiting for outbound datagram")
			return nil, time.Time{}
		}
	}
	dialog, t0 := recv(time.Second)
	if !bytes.Equal(dialog, legend) {
		t.Fatalf("first datagram is not the dialog legend: len=%d", len(dialog))
	}
	initiation, t1 := recv(2 * time.Second)
	if len(initiation) < 2 || initiation[0] != 0xEE {
		t.Fatalf("second datagram is not the sealed initiation: len=%d", len(initiation))
	}
	if gap := t1.Sub(t0); gap < 150*time.Millisecond {
		t.Fatalf("initiation followed the dialog after only %v — prelude wait skipped?", gap)
	}
	if m.sealCalls.Load() != 1 {
		t.Fatalf("initiation must pass through Seal exactly once, got %d", m.sealCalls.Load())
	}
}
