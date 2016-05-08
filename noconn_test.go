package secretstream

import (
	"io"
	"net"
	"testing"
	"time"
)

type noAddr struct{}

func (a *noAddr) Network() string {
	return "none"
}

func (a *noAddr) String() string {
	return "none"
}

type noConn struct{}

func (c *noConn) Write(_ []byte) (int, error) {
	return 0, nil
}

func (c *noConn) Read(_ []byte) (int, error) {
	return 0, nil
}

func (c *noConn) LocalAddr() net.Addr {
	return &noAddr{}
}

func (c *noConn) RemoteAddr() net.Addr {
	return &noAddr{}
}

func (c *noConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *noConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *noConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (c *noConn) Close() error {
	return nil
}

func TestNoconn(t *testing.T) {
	pr, pw := io.Pipe()

	conn := Conn{Writer: pw, Reader: pr, conn: &noConn{}}

	go conn.Write([]byte("hallo welt"))

	rx := make([]byte, 10)

	conn.Read(rx)

	if string(rx) != "hallo welt" {
		t.Fatal("mismatch")
	}

	conn.Writer.(io.Closer).Close()
	_, err := conn.Read(rx)
	if err != io.EOF {
		t.Fatal("expected EOF")
	}
}
