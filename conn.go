/*
This file is part of secretstream.

secretstream is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

secretstream is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with secretstream.  If not, see <http://www.gnu.org/licenses/>.
*/

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
