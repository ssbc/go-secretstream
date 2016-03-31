package shs

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/errgo.v1"
)

type State struct {
	appKey, remoteAppMac, secHash []byte

	localExchange  KeyPair
	local          KeyPair
	remoteExchange KeyPair

	secret, secret2 [32]byte

	remotePubKey [32]byte
}

type KeyPair struct {
	Public [32]byte
	Secret [64]byte
}

func NewState(appKey []byte, local KeyPair) (*State, error) {
	pubKey, secKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errgo.Notef(err, "shs: ephemeral generateKey() failed")
	}

	s := State{
		appKey: appKey,
	}
	s.localExchange.Public = *pubKey
	s.localExchange.Secret = *secKey
	s.local = local

	return &s, nil
}

func (s *State) CreateChallenge() []byte {
	appMac := hmac.New(sha256.New, s.appKey)
	appMac.Write(s.localExchange.Public[:])
	return append(appMac.Sum(nil), s.localExchange.Public[:]...)
}

func (s *State) VerifyChallenge(ch []byte) bool {
	mac := ch[:32]
	remotePubKey := ch[32:]
	appMac := hmac.New(sha256.New, s.appKey)
	appMac.Write(remotePubKey)
	if !hmac.Equal(mac, appMac.Sum(nil)) {
		return false
	}

	copy(s.remoteExchange.Public[:], remotePubKey)
	s.remoteAppMac = mac

	// box.Precompute() does salsa hash
	var cvSec [32]byte
	extra25519.PrivateKeyToCurve25519(&cvSec, &s.local.Secret)
	curve25519.ScalarMult(&s.secret, &s.remoteExchange.Public, &cvSec)
	secHasher := sha256.New()
	secHasher.Write(s.secret[:])
	s.secHash = secHasher.Sum(nil)
	return true
}

func (s *State) CreateClientAuth() []byte {
	var aBob [32]byte
	var cvSec [32]byte
	var curveRemotePubKey [32]byte
	extra25519.PublicKeyToCurve25519(&curveRemotePubKey, &s.remotePubKey)
	extra25519.PrivateKeyToCurve25519(&cvSec, &s.local.Secret)
	curve25519.ScalarMult(&aBob, &curveRemotePubKey, &cvSec)

	secHasher := sha256.New()
	secHasher.Write(s.appKey)
	secHasher.Write(s.secret[:])
	secHasher.Write(aBob[:])

	s2 := secHasher.Sum(nil)
	copy(s.secret2[:], s2)

	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.remotePubKey[:])
	sigMsg.Write(s.secHash)

	sig := ed25519.Sign(&s.local.Secret, sigMsg.Bytes())

	var hello bytes.Buffer
	hello.Write(sig[:])
	hello.Write(s.local.Public[:])
	var out []byte
	var nonce [24]byte
	box.SealAfterPrecomputation(out, hello.Bytes(), &nonce, &s.secret2)
	return out
}

func (s *State) VerifyClientAuth() bool {
	return false

}
