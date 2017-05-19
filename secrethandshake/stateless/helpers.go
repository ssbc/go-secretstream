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

package stateless

import "crypto/sha256"

// Remote returns the public key of the remote party
func (s *State) Remote() []byte {
	return s.remotePublic[:]
}

// GetBoxstreamEncKeys returns the encryption key and nonce suitable for boxstream
func (s *State) GetBoxstreamEncKeys() ([32]byte, [24]byte) {
	// TODO: error before cleanSecrets() has been called?

	var enKey [32]byte
	h := sha256.New()
	h.Write(s.secret[:])
	h.Write(s.remotePublic[:])
	copy(enKey[:], h.Sum(nil))

	var nonce [24]byte
	copy(nonce[:], s.remoteAppMac)
	return enKey, nonce
}

// GetBoxstreamDecKeys returns the decryption key and nonce suitable for boxstream
func (s *State) GetBoxstreamDecKeys() ([32]byte, [24]byte) {
	// TODO: error before cleanSecrets() has been called?

	var deKey [32]byte
	h := sha256.New()
	h.Write(s.secret[:])
	h.Write(s.local.Public[:])
	copy(deKey[:], h.Sum(nil))

	var nonce [24]byte
	copy(nonce[:], s.localAppMac)
	return deKey, nonce
}

// cleanSecrets overwrites all intermediate secrets and copies the final secret to s.secret
// func (s *State) cleanSecrets() {
// 	var zeros [64]byte

// 	copy(s.secHash, zeros[:])
// 	copy(s.secret[:], zeros[:]) // redundant
// 	copy(s.aBob[:], zeros[:])
// 	copy(s.bAlice[:], zeros[:])

// 	h := sha256.New()
// 	h.Write(s.secret3[:])
// 	copy(s.secret[:], h.Sum(nil))
// 	copy(s.secret2[:], zeros[:])
// 	copy(s.secret3[:], zeros[:])
// 	copy(s.localExchange.Secret[:], zeros[:])
// }
