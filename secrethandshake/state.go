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

package secrethandshake

import (
	"github.com/agl/ed25519"
	"github.com/cryptix/secretstream/secrethandshake/stateless"
)

// NewClientState initializes the state for the client side
func NewClientState(appKey string, local stateless.EdKeyPair, remotePublic [ed25519.PublicKeySize]byte) (*stateless.State, error) {
	return stateless.Initialize(
		stateless.SetAppKeyFromB64(appKey),
		stateless.LocalKey(local),
		stateless.RemotePub(remotePublic),
	)
}

// NewServerState initializes the state for the server side
func NewServerState(appKey string, local stateless.EdKeyPair) (*stateless.State, error) {
	return stateless.Initialize(
		stateless.SetAppKeyFromB64(appKey),
		stateless.LocalKey(local),
	)
}
