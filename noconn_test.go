package secretstream

import (
	"io"
	"testing"
)

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
