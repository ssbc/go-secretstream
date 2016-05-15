package secretstream

import (
	"errors"
	"net"
)

// ErrOnlyTCP is returned if a progrems tries to open a UDP socket through secretstream
var ErrOnlyTCP = errors.New("secretstream: only TCP is supported")

// Dialer is the same signature as net.Dial, there is no expoted interface for this
type Dialer func(net, addr string) (net.Conn, error)

// Listener can accept secret handshakes
type Listener struct {
	l net.Listener
	s *Server
}

// Addr returns the
func (l Listener) Addr() net.Addr {
	return Addr{l.l.Addr(), l.s.keyPair.Public[:]}
}

// Close closes the underlying net.Listener
func (l Listener) Close() error {
	return l.l.Close()
}

// Accept accepts a connection on the underlying net.Listener
// and expects to receive a handshake
func (l Listener) Accept() (net.Conn, error) {
	c, err := l.l.Accept()
	if err != nil {
		return nil, err
	}

	return ServerOnce(c, l.s.keyPair, l.s.appKey)
}
