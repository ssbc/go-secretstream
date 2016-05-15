package secretstream

import (
	"io"
	"net"
	"time"
)

// Addr wrapps a net.Addr and adds the public key
type Addr struct {
	net.Addr
	pubKey []byte
}

// Network returns the network type of the net.Addr and appends /secret to it
// TODO(cryptix): the appended string might interfer with callers expecting "tcp"?
func (a Addr) Network() string {
	return a.Addr.Network() + "/secret"
}

// PubKey returns the corrosponding public key for this connection
func (a Addr) PubKey() []byte {
	return a.pubKey
}

// Conn is a boxstream wrapped net.Conn
type Conn struct {
	io.Reader
	io.Writer
	conn net.Conn

	// public keys
	local, remote []byte
}

// Close closes the underlying net.Conn
func (c Conn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local net.Addr with the local public key
func (c Conn) LocalAddr() net.Addr {
	return Addr{c.conn.LocalAddr(), c.local}
}

// RemoteAddr returns the remote net.Addr with the remote public key
func (c Conn) RemoteAddr() net.Addr {
	return Addr{c.conn.RemoteAddr(), c.remote}
}

// SetDeadline passes the call to the underlying net.Conn
func (c Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline passes the call to the underlying net.Conn
func (c Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline passes the call to the underlying net.Conn
func (c Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
