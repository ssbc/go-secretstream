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
	"log"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

func ClientCreateAuth(state *State) []byte {
	var n [24]byte
	return box.SealAfterPrecomputation(nil, state.localHello, &n, &state.secret2)
}

func ServerVerifyAuth(state *State, data []byte) *State {
	var cvSec, aBob [32]byte
	extra25519.PrivateKeyToCurve25519(&cvSec, &state.local.Secret)
	curve25519.ScalarMult(&aBob, &cvSec, &state.ephKeyRemotePub)
	copy(state.aBob[:], aBob[:])

	secHasher := sha256.New()
	secHasher.Write(state.appKey)
	secHasher.Write(state.secret[:])
	secHasher.Write(state.aBob[:])
	copy(state.secret2[:], secHasher.Sum(nil))

	state.remoteHello = make([]byte, 0, len(data)-16)

	var nonce [24]byte
	var openOk bool
	state.remoteHello, openOk = box.OpenAfterPrecomputation(state.remoteHello, data, &nonce, &state.secret2)

	if !openOk { // don't panic on the next copy
		log.Println("secretHandshake/ServerVerifyAuth: open not OK!!")
		state.remoteHello = make([]byte, len(data)-16)
	}

	var sig [ed25519.SignatureSize]byte
	copy(sig[:], state.remoteHello[:ed25519.SignatureSize])
	var public [ed25519.PublicKeySize]byte
	copy(public[:], state.remoteHello[ed25519.SignatureSize:])

	var sigMsg bytes.Buffer
	sigMsg.Write(state.appKey)
	sigMsg.Write(state.local.Public[:])
	sigMsg.Write(state.secHash)
	verifyOk := ed25519.Verify(&public, sigMsg.Bytes(), &sig)
	copy(state.remotePublic[:], public[:])

	var curveRemotePubKey [32]byte
	extra25519.PublicKeyToCurve25519(&curveRemotePubKey, &state.remotePublic)
	var bAlice [32]byte
	curve25519.ScalarMult(&bAlice, &state.ephKeyPair.Secret, &curveRemotePubKey)
	copy(state.bAlice[:], bAlice[:])

	sh3 := sha256.New()
	sh3.Write(state.appKey)
	sh3.Write(state.secret[:])
	sh3.Write(state.aBob[:])
	sh3.Write(state.bAlice[:])
	copy(state.secret3[:], sh3.Sum(nil))

	if !(openOk && verifyOk) {
		state = nil
	}
	return state
}
