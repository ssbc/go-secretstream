// SPDX-License-Identifier: MIT

package secretstream

import (
	"encoding/base64"
	"io"
	"net"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"go.cryptoscope.co/netwrap"
)

const NetworkString = "shs-bs"

// Addr wrapps a net.Addr and adds the public key
type Addr struct {
	PubKey []byte
}

// Network returns NetworkString, the network id of this protocol.
// Can be used with go.cryptoscope.co/netwrap to wrap the underlying connection.
func (a Addr) Network() string {
	return NetworkString
}

func (a Addr) String() string {
	// TODO keks: is this the address format we want to use?
	return "@" + base64.StdEncoding.EncodeToString(a.PubKey) + ".ed25519"
}

// Conn is a boxstream wrapped net.Conn
type Conn struct {
	io.Reader
	io.WriteCloser
	conn net.Conn

	// public keys
	local, remote []byte
}

// Close closes the underlying net.Conn
func (conn *Conn) Close() error {
	werr := conn.WriteCloser.Close()
	cerr := conn.conn.Close()

	werr = errors.Wrap(werr, "boxstream: error closing boxer")
	cerr = errors.Wrap(cerr, "boxstream: error closing conn")

	if werr != nil && cerr != nil {
		return errors.Wrap(multierror.Append(werr, cerr), "error closing both boxer and conn")
	}

	if werr != nil {
		return werr
	}

	if cerr != nil {
		return cerr
	}

	return nil
}

// LocalAddr returns the local net.Addr with the local public key
func (conn *Conn) LocalAddr() net.Addr {
	return netwrap.WrapAddr(conn.conn.LocalAddr(), Addr{conn.local})
}

// RemoteAddr returns the remote net.Addr with the remote public key
func (conn *Conn) RemoteAddr() net.Addr {
	return netwrap.WrapAddr(conn.conn.RemoteAddr(), Addr{conn.remote})
}

// SetDeadline passes the call to the underlying net.Conn
func (conn *Conn) SetDeadline(t time.Time) error {
	return conn.conn.SetDeadline(t)
}

// SetReadDeadline passes the call to the underlying net.Conn
func (conn *Conn) SetReadDeadline(t time.Time) error {
	return conn.conn.SetReadDeadline(t)
}

// SetWriteDeadline passes the call to the underlying net.Conn
func (conn *Conn) SetWriteDeadline(t time.Time) error {
	return conn.conn.SetWriteDeadline(t)
}
