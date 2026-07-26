package device

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// TestHeaderProtectionBrokenByWARPReservedClear documents why sagernet's
// UDP[1:4] reserved-byte clear must be skipped for AmneziaWG: those bytes are
// part of the S-padding ChaCha20 nonce when header_protection_key is set.
// amneziawg-go has no such rewrite; our bind SetSkipReserved mirrors that.
func TestHeaderProtectionBrokenByWARPReservedClear(t *testing.T) {
	var key HeaderCipherKey
	for i := range key {
		key[i] = byte(i + 1)
	}
	padding := 16
	plainType := uint32(1001)

	wire := make([]byte, padding+MessageInitiationSize)
	for i := 0; i < padding; i++ {
		wire[i] = byte(0xA0 + i)
	}
	binary.LittleEndian.PutUint32(wire[padding:], plainType)
	for i := padding + 4; i < len(wire); i++ {
		wire[i] = byte(i)
	}

	cip, err := chacha20.NewUnauthenticatedCipher(key[:], wire[:HeaderCipherNonceSize])
	if err != nil {
		t.Fatal(err)
	}
	cip.XORKeyStream(wire[padding:], wire[padding:])

	decryptType := func(pkt []byte) uint32 {
		c, err := chacha20.NewUnauthenticatedCipher(key[:], pkt[:HeaderCipherNonceSize])
		if err != nil {
			t.Fatal(err)
		}
		th := make([]byte, 4)
		c.XORKeyStream(th, th)
		var out [4]byte
		for i := 0; i < 4; i++ {
			out[i] = pkt[padding+i] ^ th[i]
		}
		return binary.LittleEndian.Uint32(out[:])
	}

	if got := decryptType(wire); got != plainType {
		t.Fatalf("intact wire: type=%d want %d", got, plainType)
	}

	corrupted := append([]byte{}, wire...)
	corrupted[1], corrupted[2], corrupted[3] = 0, 0, 0 // WARP reserved clear
	if got := decryptType(corrupted); got == plainType {
		t.Fatal("expected reserved clear to break HP type recovery")
	}
}

// TestInboundTUNSliceUsesSPadding mirrors amneziawg-go v3 Write prep:
// IP payload starts at buffer[padding+MessageTransportOffsetContent:].
func TestInboundTUNSliceUsesSPadding(t *testing.T) {
	padding := uint32(20)
	ip := []byte{0x45, 0x00, 0x00, 0x14}
	buf := make([]byte, int(padding)+MessageTransportOffsetContent+len(ip))
	copy(buf[int(padding)+MessageTransportOffsetContent:], ip)

	slice := buf[int(padding) : int(padding)+MessageTransportOffsetContent+len(ip)]
	got := slice[MessageTransportOffsetContent:]
	if string(got) != string(ip) {
		t.Fatalf("got %x want %x", got, ip)
	}

	wrong := buf[:MessageTransportOffsetContent+len(ip)]
	if string(wrong[MessageTransportOffsetContent:]) == string(ip) {
		t.Fatal("pre-fix slice without padding offset should not yield IP")
	}
}
