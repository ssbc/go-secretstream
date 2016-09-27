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
