package secretstream

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"time"
)

type Addr struct {
	net.Addr
	PubKey []byte
}

func (a Addr) Network() string {
	return a.Addr.Network() + "/secret"
}

func (a Addr) String() string {
	return a.Addr.String() + ":" + base64.StdEncoding.EncodeToString(a.PubKey)
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
	log.Println("WARNING: SetDeadline() not sure this works")
	return c.conn.SetDeadline(t)
}

func (c Conn) SetReadDeadline(t time.Time) error {
	log.Println("WARNING: SetReadDeadline() not sure this works")
	return c.conn.SetReadDeadline(t)
}

func (c Conn) SetWriteDeadline(t time.Time) error {
	log.Println("WARNING: SetWriteDeadline() not sure this works")
	return c.conn.SetWriteDeadline(t)
}
