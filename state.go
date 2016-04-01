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
	remoteExchange KeyPair // TODO: also only ExchangePublic in practice
	remotePublic   [ed25519.PublicKeySize]byte

	secret, secret2, secret3 [32]byte

	remoteHello []byte

	aBob, bAlice [32]byte // better name? helloAlice, helloBob?
}

// and agl/ed25519 keypair
// dont forget to use extra25519 to convert to curve25519
type KeyPair struct {
	Public [ed25519.PublicKeySize]byte
	Secret [ed25519.PrivateKeySize]byte
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

	var cvSec [32]byte
	extra25519.PrivateKeyToCurve25519(&cvSec, &s.local.Secret)
	curve25519.ScalarMult(&s.secret, &s.remoteExchange.Public, &cvSec)
	secHasher := sha256.New()
	secHasher.Write(s.secret[:])
	s.secHash = secHasher.Sum(nil)
	return true
}

func (s *State) CreateClientAuth() []byte {

	var curveRemotePubKey [32]byte
	extra25519.PublicKeyToCurve25519(&curveRemotePubKey, &s.remotePublic)
	var cvSec [32]byte
	extra25519.PrivateKeyToCurve25519(&cvSec, &s.local.Secret)
	curve25519.ScalarMult(&s.aBob, &curveRemotePubKey, &cvSec)

	secHasher := sha256.New()
	secHasher.Write(s.appKey)
	secHasher.Write(s.secret[:])
	secHasher.Write(s.aBob[:])
	copy(s.secret2[:], secHasher.Sum(nil))

	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.remotePublic[:])
	sigMsg.Write(s.secHash)

	sig := ed25519.Sign(&s.local.Secret, sigMsg.Bytes())

	var hello bytes.Buffer
	hello.Write(sig[:])
	hello.Write(s.local.Public[:])
	var out []byte
	var nonce [24]byte // always 0?
	_ = box.SealAfterPrecomputation(out, hello.Bytes(), &nonce, &s.secret2)
	// TODO i have a funny feeling about this one.. there is an additinal return argument that gets discarded
	return out
}

func (s *State) VerifyClientAuth(data []byte) bool {
	var curveRemotePubKey [32]byte
	extra25519.PublicKeyToCurve25519(&curveRemotePubKey, &s.remotePublic)
	var cvSec [32]byte
	extra25519.PrivateKeyToCurve25519(&cvSec, &s.local.Secret)
	curve25519.ScalarMult(&s.aBob, &curveRemotePubKey, &cvSec)

	secHasher := sha256.New()
	secHasher.Write(s.appKey)
	secHasher.Write(s.secret[:])
	secHasher.Write(s.aBob[:])
	copy(s.secret2[:], secHasher.Sum(nil))

	var nonce [24]byte // always 0?
	_, ok := box.OpenAfterPrecomputation(s.remoteHello, data, &nonce, &s.secret2)
	if !ok {
		return false
	}

	var sig [ed25519.SignatureSize]byte
	copy(sig[:], s.remoteHello[:ed25519.SignatureSize])
	var public [ed25519.PublicKeySize]byte
	copy(public[:], s.remoteHello[ed25519.SignatureSize:]) // TODO: size difference. JS .slice(64,client_auth_length)  (var client_auth_length = 16+32+64)

	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.local.Public[:])
	sigMsg.Write(s.secHash)
	if !ed25519.Verify(&public, sigMsg.Bytes(), &sig) {
		return false
	}

	copy(s.remotePublic[:], public[:])
	return true
}

func (s *State) CreateServerAccept() []byte {
	var curveRemotePubKey [32]byte
	extra25519.PublicKeyToCurve25519(&curveRemotePubKey, &s.remotePublic)
	var curveExchangeSec [32]byte
	extra25519.PrivateKeyToCurve25519(&curveExchangeSec, &s.localExchange.Secret)
	curve25519.ScalarMult(&s.bAlice, &curveRemotePubKey, &curveExchangeSec)

	secHasher := sha256.New()
	secHasher.Write(s.appKey)
	secHasher.Write(s.secret[:])
	secHasher.Write(s.aBob[:])
	secHasher.Write(s.bAlice[:])
	copy(s.secret3[:], secHasher.Sum(nil))

	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.remoteHello[:])
	sigMsg.Write(s.secHash)

	okay := ed25519.Sign(&s.local.Secret, sigMsg.Bytes())

	var out []byte
	var nonce [24]byte // always 0?
	box.SealAfterPrecomputation(out, okay[:], &nonce, &s.secret3)
	return out
}

func (s *State) VerifyServerAccept(boxedOkay []byte) bool {
	var curveRemotePubKey [32]byte
	extra25519.PublicKeyToCurve25519(&curveRemotePubKey, &s.remotePublic)
	var curveExchangeSec [32]byte
	extra25519.PrivateKeyToCurve25519(&curveExchangeSec, &s.localExchange.Secret)
	curve25519.ScalarMult(&s.bAlice, &curveRemotePubKey, &curveExchangeSec)

	secHasher := sha256.New()
	secHasher.Write(s.appKey)
	secHasher.Write(s.secret[:])
	secHasher.Write(s.aBob[:])
	secHasher.Write(s.bAlice[:])
	copy(s.secret3[:], secHasher.Sum(nil))

	var out []byte
	var nonce [24]byte // always 0?
	_, ok := box.OpenAfterPrecomputation(out, boxedOkay, &nonce, &s.secret3)
	if !ok {
		return false
	}

	// TODO: length check?
	var sig [ed25519.SignatureSize]byte
	copy(sig[:], out)

	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.remoteHello[:])
	sigMsg.Write(s.secHash)

	return ed25519.Verify(&s.remotePublic, sigMsg.Bytes(), &sig)
}

func (s *State) CleanSecrets() {
	var zeros [64]byte

	copy(s.secHash, zeros[:])
	copy(s.secret[:], zeros[:]) // redundant
	copy(s.aBob[:], zeros[:])
	copy(s.bAlice[:], zeros[:])

	copy(s.secret[:], sha256.New().Sum(s.secret3[:]))
	copy(s.secret2[:], zeros[:])
	copy(s.secret3[:], zeros[:])
	copy(s.localExchange.Secret[:], zeros[:])
}
