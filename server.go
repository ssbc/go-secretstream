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
	"net"
	"strings"

	"github.com/cryptix/secretstream/boxstream"
	"github.com/cryptix/secretstream/secrethandshake"
)

// Server can create net.Listeners
type Server struct {
	keyPair secrethandshake.EdKeyPair
	appKey  []byte
}

// NewServer returns a Server which uses the passed keyPair and appKey
func NewServer(keyPair secrethandshake.EdKeyPair, appKey []byte) (*Server, error) {
	return &Server{keyPair: keyPair, appKey: appKey}, nil
}

// Listen opens a net.Listener which accepts only secrethandshake connections
func (s Server) Listen(n, a string) (net.Listener, error) {
	if !strings.HasPrefix(n, "tcp") {
		return nil, ErrOnlyTCP
	}
	l, err := net.Listen(n, a)
	if err != nil {
		return nil, err
	}

	return &Listener{l: l, s: &s}, nil
}

// ServerOnce wraps the passed net.Conn into a boxstream if the handshake is successful
func ServerOnce(conn net.Conn, secretKey secrethandshake.EdKeyPair, appKey []byte) (net.Conn, error) {
	state, err := secrethandshake.NewServerState(appKey, secretKey)
	if err != nil {
		return nil, err
	}

	err = secrethandshake.Server(state, conn)
	if err != nil {
		return nil, err
	}

	enKey, enNonce := state.GetBoxstreamEncKeys()
	deKey, deNonce := state.GetBoxstreamDecKeys()

	remote := state.Remote()
	boxed := Conn{
		Reader: boxstream.NewUnboxer(conn, &deNonce, &deKey),
		Writer: boxstream.NewBoxer(conn, &enNonce, &enKey),
		conn:   conn,
		local:  secretKey.Public[:],
		remote: remote[:],
	}

	return boxed, nil
}
