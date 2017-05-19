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

import (
	"bytes"
	"crypto/sha256"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

func ServerCreateAccept(s *State) []byte {
	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.remoteHello[:])
	sigMsg.Write(s.secHash)
	okay := ed25519.Sign(&s.local.Secret, sigMsg.Bytes())

	var out = make([]byte, 0, len(okay)+16)
	var nonce [24]byte
	out = box.SealAfterPrecomputation(out, okay[:], &nonce, &s.secret3)
	return out
}

func ClientVerifyAccept(s *State, acceptmsg []byte) *State {
	var curveLocalSec [32]byte
	extra25519.PrivateKeyToCurve25519(&curveLocalSec, &s.local.Secret)
	var bAlice [32]byte
	curve25519.ScalarMult(&bAlice, &curveLocalSec, &s.ephKeyRemotePub)
	copy(s.bAlice[:], bAlice[:])

	secHasher := sha256.New()
	secHasher.Write(s.appKey)
	secHasher.Write(s.secret[:])
	secHasher.Write(s.aBob[:])
	secHasher.Write(s.bAlice[:])
	copy(s.secret3[:], secHasher.Sum(nil))

	var nonce [24]byte
	out := make([]byte, 0, len(acceptmsg)-16)
	out, openOk := box.OpenAfterPrecomputation(out, acceptmsg, &nonce, &s.secret3)

	var sig [ed25519.SignatureSize]byte
	copy(sig[:], out)

	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.localHello[:])
	sigMsg.Write(s.secHash)

	verifyOK := ed25519.Verify(&s.remotePublic, sigMsg.Bytes(), &sig)
	if !(verifyOK && openOk) {
		s = nil
	}
	return s
}
