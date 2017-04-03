package stateless

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

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
	if ok {
		// TODO: not fully functional
		// it's not a copy of the original but the same pointer..
		return state
	} else {
		return nil
	}
}
