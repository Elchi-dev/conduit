package mqttx

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

// chunks returns its data in reads of at most n bytes.
type chunks struct {
	net.Conn
	r io.Reader
}

func (c *chunks) Read(p []byte) (int, error) { return c.r.Read(p) }

func TestGuard(t *testing.T) {
	// A small packet, a pingresp, then a publish claiming 2 MiB.
	stream := []byte{0x30, 0x03, 'a', 'b', 'c', 0xd0, 0x00, 0x30, 0x80, 0x80, 0x80, 0x01}
	g := &guard{Conn: &chunks{r: bytes.NewReader(stream)}, max: MaxPacket}
	got, err := io.ReadAll(g)
	if !errors.Is(err, ErrTooBig) || !bytes.Equal(got, stream[:7]) {
		t.Fatalf("%x %v", got, err)
	}
	// Split across reads, a packet at the limit passes.
	ok := append([]byte{0x30, 0x80, 0x80, 0x01}, bytes.Repeat([]byte{'x'}, 16384)...)
	g = &guard{Conn: &chunks{r: io.MultiReader(bytes.NewReader(ok[:2]), bytes.NewReader(ok[2:9]), bytes.NewReader(ok[9:]))}, max: 16384}
	if got, err := io.ReadAll(g); err != nil || len(got) != len(ok) {
		t.Fatalf("%d %v", len(got), err)
	}
	g = &guard{Conn: &chunks{r: bytes.NewReader([]byte{0x30, 0xff, 0xff, 0xff, 0xff, 0x01})}, max: 1 << 30}
	if _, err := io.ReadAll(g); err == nil {
		t.Fatal("accepted a five-byte length")
	}
}
