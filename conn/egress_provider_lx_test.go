package conn

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

type fakeEgress struct {
	port     uint16
	recvN    int
	recvSrc  netip.AddrPort
	recvErr  error
	lookup   *net.UDPConn
	setCalls []uint16
}

func (f *fakeEgress) SetEgressPort(port uint16) bool {
	f.setCalls = append(f.setCalls, port)
	f.port = port
	return true
}

func (f *fakeEgress) LookupEgress(destination netip.AddrPort) *net.UDPConn {
	return f.lookup
}

func (f *fakeEgress) ReceiveEgress(buffer []byte) (int, netip.AddrPort, error) {
	if f.recvErr != nil {
		return 0, netip.AddrPort{}, f.recvErr
	}
	n := f.recvN
	if n > len(buffer) {
		n = len(buffer)
	}
	for i := 0; i < n; i++ {
		buffer[i] = byte(i + 1)
	}
	return n, f.recvSrc, nil
}

func TestSetEgressProviderOpenClose(t *testing.T) {
	bind := NewStdNetBind(nil).(*StdNetBind)
	provider := &fakeEgress{
		recvN:   8,
		recvSrc: netip.MustParseAddrPort("1.1.1.1:51820"),
	}
	bind.SetEgressProvider(provider)

	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if port == 0 {
		t.Fatal("expected ephemeral port")
	}
	if len(provider.setCalls) == 0 || provider.setCalls[0] != port {
		t.Fatalf("SetEgressPort on Open: got %v want [%d]", provider.setCalls, port)
	}
	if len(fns) < 2 {
		// at least one IP family receive + egress receive
		t.Fatalf("expected egress receive fn among %d funcs", len(fns))
	}

	egressFn := fns[len(fns)-1]
	bufs := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	eps := make([]Endpoint, 1)
	n, err := egressFn(bufs, sizes, eps)
	if err != nil || n != 1 || sizes[0] != 8 {
		t.Fatalf("egress receive: n=%d sizes=%v err=%v", n, sizes, err)
	}
	if eps[0].(*StdNetEndpoint).AddrPort != provider.recvSrc {
		t.Fatalf("endpoint = %v", eps[0])
	}
	// skipReserved=false → reserved clear on bytes 1-3
	if bufs[0][1] != 0 || bufs[0][2] != 0 || bufs[0][3] != 0 {
		t.Fatalf("expected reserved clear, got %v", bufs[0][:8])
	}

	_ = bind.Close()
	if provider.setCalls[len(provider.setCalls)-1] != 0 {
		t.Fatalf("SetEgressPort(0) on Close: %v", provider.setCalls)
	}
}

func TestEgressReceiveSkipsReservedClearForAWG(t *testing.T) {
	bind := NewStdNetBind(nil).(*StdNetBind)
	bind.SetSkipReserved(true)
	provider := &fakeEgress{
		recvN:   8,
		recvSrc: netip.MustParseAddrPort("1.1.1.1:51820"),
	}
	bind.SetEgressProvider(provider)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()

	bufs := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	eps := make([]Endpoint, 1)
	_, err = fns[len(fns)-1](bufs, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	// With skipReserved, bytes 1-3 keep ReceiveEgress payload (2,3,4)
	if bufs[0][1] != 2 || bufs[0][2] != 3 || bufs[0][3] != 4 {
		t.Fatalf("AWG magic must survive egress rx clear: %v", bufs[0][:8])
	}
}

func TestEgressReceivePropagatesError(t *testing.T) {
	bind := NewStdNetBind(nil).(*StdNetBind)
	provider := &fakeEgress{recvErr: errors.New("closed")}
	bind.SetEgressProvider(provider)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	_, err = fns[len(fns)-1]([][]byte{make([]byte, 16)}, make([]int, 1), make([]Endpoint, 1))
	if err == nil {
		t.Fatal("expected error")
	}
}
