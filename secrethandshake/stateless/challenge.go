package stateless

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

func CreateChallenge(state *State) []byte {
	return append(state.localAppMac, state.ephKeyPair.Public[:]...)
}

func VerifyChallenge(state *State, ch []byte) *State {
	mac := ch[:32]
	remoteEphPubKey := ch[32:]

	appMac := hmac.New(sha512.New, state.appKey[:32])
	appMac.Write(remoteEphPubKey)
	ok := hmac.Equal(appMac.Sum(nil)[:32], mac)

	copy(state.ephKeyRemotePub[:], remoteEphPubKey)
	state.remoteAppMac = mac

	var sec [32]byte
	curve25519.ScalarMult(&sec, &state.ephKeyPair.Secret, &state.ephKeyRemotePub)
	copy(state.secret[:], sec[:])

	secHasher := sha256.New()
	secHasher.Write(state.secret[:])
	state.secHash = secHasher.Sum(nil)

	if !ok { // do this last to not introduce timing sidechannels
		state = nil
	}
	// TODO: not fully functional
	// it's not a copy of the original but the same pointer..
	return state
}

func ClientVerifyChallenge(state *State, ch []byte) *State {
	state = VerifyChallenge(state, ch)
	if state == nil {
		return nil
	}

	var cvSec, aBob [32]byte
	extra25519.PrivateKeyToCurve25519(&cvSec, &state.local.Secret)
	curve25519.ScalarMult(&aBob, &cvSec, &state.ephKeyRemotePub)
	copy(state.aBob[:], aBob[:])

	secHasher := sha256.New()
	secHasher.Write(state.appKey)
	secHasher.Write(state.secret[:])
	secHasher.Write(state.aBob[:])
	copy(state.secret2[:], secHasher.Sum(nil))

	var sigMsg bytes.Buffer
	sigMsg.Write(state.appKey)
	sigMsg.Write(state.remotePublic[:])
	sigMsg.Write(state.secHash)

	sig := ed25519.Sign(&state.local.Secret, sigMsg.Bytes())

	var helloBuf bytes.Buffer
	helloBuf.Write(sig[:])
	helloBuf.Write(state.local.Public[:])
	state.hello = helloBuf.Bytes()
	return state
}
