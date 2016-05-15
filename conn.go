package secretstream

import (
	"io"
	"net"
	"time"
)

type Addr struct {
	net.Addr
	pubKey []byte
}

func (a Addr) Network() string {
	return a.Addr.Network() + "/secret"
}

func (a Addr) String() string {
	return a.Addr.String() // + ":" + base64.StdEncoding.EncodeToString(a.PubKey) // breaks dialing
}

func (a Addr) PubKey() []byte {
	return a.pubKey
}

type Conn struct {
	io.Reader
	io.Writer
	conn net.Conn

	// public keys
	local, remote []byte
}

func (c Conn) Close() error {
	return c.conn.Close()
}

func (c Conn) LocalAddr() net.Addr {
	return Addr{c.conn.LocalAddr(), c.local}
}

func (c Conn) RemoteAddr() net.Addr {
	return Addr{c.conn.RemoteAddr(), c.remote}
}

func (c Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
