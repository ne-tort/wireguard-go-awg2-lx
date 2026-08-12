//go:build windows

package conn_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
)

// Regression: Go 1.26 WriteMsgUDP/ReadMsgUDP on Windows fail for non-nil empty
// oob. StdNetBind must pass nil when sticky/GSO control is unused.
func TestStdNetBindEmptyOOBRoundTrip(t *testing.T) {
	recv := conn.NewStdNetBind(nil)
	defer recv.Close()
	fns, port, err := recv.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) == 0 {
		t.Fatal("no receive funcs")
	}

	send := conn.NewStdNetBind(nil)
	defer send.Close()
	if _, _, err := send.Open(0); err != nil {
		t.Fatal(err)
	}
	ep, err := send.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		eps := make([]conn.Endpoint, 1)
		_, err := fns[0](bufs, sizes, eps)
		if err != nil {
			done <- err
			return
		}
		if sizes[0] != 4 || bufs[0][0] != 'p' {
			done <- fmt.Errorf("unexpected payload n=%d data=%q", sizes[0], bufs[0][:sizes[0]])
			return
		}
		done <- nil
	}()

	time.Sleep(20 * time.Millisecond)
	if err := send.Send([][]byte{[]byte("ping")}, ep, 0); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for receive")
	}
}
