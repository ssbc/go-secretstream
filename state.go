package shs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log"

	"github.com/GoKillers/libsodium-go/cryptoauth"
	"github.com/GoKillers/libsodium-go/cryptobox"
	"github.com/GoKillers/libsodium-go/cryptosecretbox"
	"github.com/GoKillers/libsodium-go/scalarmult"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/nacl/box"
)

// State is the state each peer holds during the handshake
type State struct {
	appKey, remoteAppMac, secHash []byte

	localExchange  KeyPair
	local          KeyPair
	remoteExchange KeyPair                     // TODO: also only ExchangePublic in practice
	remotePublic   [ed25519.PublicKeySize]byte // long-term

	secret, secret2, secret3 [32]byte

	hello []byte

	aBob, bAlice [32]byte // better name? helloAlice, helloBob?
}

// KeyPair is a keypair for use with github.com/agl/ed25519
type KeyPair struct {
	Public [ed25519.PublicKeySize]byte
	Secret [ed25519.PrivateKeySize]byte
}

// NewClientState initializes the state for the client side
func NewClientState(appKey []byte, local KeyPair, remotePublic [ed25519.PublicKeySize]byte) (*State, error) {
	state, err := newState(appKey, local)
	if err != nil {
		return state, err
	}

	state.remotePublic = remotePublic

	return state, err
}

// NewServerState initializes the state for the server side
func NewServerState(appKey []byte, local KeyPair) (*State, error) {
	return newState(appKey, local)
}

// newState initializes the state needed by both client and server
func newState(appKey []byte, local KeyPair) (*State, error) {
	seedA := make([]byte, cryptobox.CryptoBoxSeedBytes())
	io.ReadFull(rand.Reader, seedA)

	secKey, pubKey, _ := cryptobox.CryptoBoxSeedKeyPair(seedA)

	s := State{
		appKey: appKey,
	}
	copy(s.localExchange.Public[:], pubKey)
	copy(s.localExchange.Secret[:], secKey)
	s.local = local

	return &s, nil
}

// createChallenge returns a buffer with a challenge
func (s *State) createChallenge() []byte {
	appMac, _ := cryptoauth.CryptoAuth(s.localExchange.Public[:], s.appKey[:32])
	return append(appMac[:32], s.localExchange.Public[:]...)
}

// verifyChallenge returns whether the passed buffer is valid
func (s *State) verifyChallenge(ch []byte) bool {
	mac := ch[:32]
	remoteEphPubKey := ch[32:]

	var ok = cryptoauth.CryptoAuthVerify(mac, remoteEphPubKey, s.appKey[:32]) == 0

	copy(s.remoteExchange.Public[:], remoteEphPubKey)
	s.remoteAppMac = mac

	sec, _ := scalarmult.CryptoScalarMult(s.localExchange.Secret[:32], s.remoteExchange.Public[:])
	copy(s.secret[:], sec)

	secHasher := sha256.New()
	secHasher.Write(s.secret[:])
	s.secHash = secHasher.Sum(nil)

	return ok
}

// createClientAuth returns a buffer containing a clientAuth message
func (s *State) createClientAuth() []byte {
	var curveRemotePubKey [32]byte
	extra25519.PublicKeyToCurve25519(&curveRemotePubKey, &s.remotePublic)
	aBob, _ := scalarmult.CryptoScalarMult(s.localExchange.Secret[:32], curveRemotePubKey[:])
	copy(s.aBob[:], aBob)

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

	var helloBuf bytes.Buffer
	helloBuf.Write(sig[:])
	helloBuf.Write(s.local.Public[:])
	s.hello = helloBuf.Bytes()

	var n [24]byte
	out, _ := secretbox.CryptoSecretBoxEasy(s.hello, n[:], s.secret2[:])
	return out
}

// verifyClientAuth returns whether a buffer contains a valid clientAuth message
func (s *State) verifyClientAuth(data []byte) bool {
	var cvSec [32]byte
	extra25519.PrivateKeyToCurve25519(&cvSec, &s.local.Secret)
	aBob, _ := scalarmult.CryptoScalarMult(cvSec[:], s.remoteExchange.Public[:])
	copy(s.aBob[:], aBob)

	secHasher := sha256.New()
	secHasher.Write(s.appKey)
	secHasher.Write(s.secret[:])
	secHasher.Write(s.aBob[:])
	copy(s.secret2[:], secHasher.Sum(nil))

	s.hello = make([]byte, 0, len(data)-16)

	var nonce [24]byte // always 0?
	var ok bool
	s.hello, ok = box.OpenAfterPrecomputation(s.hello, data, &nonce, &s.secret2)
	if !ok {
		log.Println("server/VerifyClientAuth: couldn't open box")
		return false
	}

	var sig [ed25519.SignatureSize]byte
	copy(sig[:], s.hello[:ed25519.SignatureSize])
	var public [ed25519.PublicKeySize]byte
	copy(public[:], s.hello[ed25519.SignatureSize:])

	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.local.Public[:])
	sigMsg.Write(s.secHash)
	if !ed25519.Verify(&public, sigMsg.Bytes(), &sig) {
		log.Println("server/VerifyClientAuth: couldn't verify sig")
		return false
	}

	copy(s.remotePublic[:], public[:])
	return true
}

// createServerAccept returns a buffer containing a serverAccept message
func (s *State) createServerAccept() []byte {
	var curveRemotePubKey [32]byte
	extra25519.PublicKeyToCurve25519(&curveRemotePubKey, &s.remotePublic)
	bAlice, _ := scalarmult.CryptoScalarMult(s.localExchange.Secret[:32], curveRemotePubKey[:])
	copy(s.bAlice[:], bAlice)

	secHasher := sha256.New()
	secHasher.Write(s.appKey)
	secHasher.Write(s.secret[:])
	secHasher.Write(s.aBob[:])
	secHasher.Write(s.bAlice[:])
	copy(s.secret3[:], secHasher.Sum(nil))

	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.hello[:])
	sigMsg.Write(s.secHash)

	okay := ed25519.Sign(&s.local.Secret, sigMsg.Bytes())

	var out = make([]byte, 0, len(okay)+16)
	var nonce [24]byte // always 0?
	return box.SealAfterPrecomputation(out, okay[:], &nonce, &s.secret3)
}

// verifyServerAccept returns whether the passed buffer contains a valid serverAccept message
func (s *State) verifyServerAccept(boxedOkay []byte) bool {
	var curveLocalSec [32]byte
	extra25519.PrivateKeyToCurve25519(&curveLocalSec, &s.local.Secret)
	bAlice, _ := scalarmult.CryptoScalarMult(curveLocalSec[:], s.remoteExchange.Public[:])
	copy(s.bAlice[:], bAlice)

	secHasher := sha256.New()
	secHasher.Write(s.appKey)
	secHasher.Write(s.secret[:])
	secHasher.Write(s.aBob[:])
	secHasher.Write(s.bAlice[:])
	copy(s.secret3[:], secHasher.Sum(nil))

	var nonce [24]byte // always 0?
	out, ex := secretbox.CryptoSecretBoxOpenEasy(boxedOkay, nonce[:], s.secret3[:])
	if ex != 0 {
		log.Println("client/VerifyServerAccept: couldn't open s3 box")
		return false
	}

	var sig [ed25519.SignatureSize]byte
	copy(sig[:], out)

	var sigMsg bytes.Buffer
	sigMsg.Write(s.appKey)
	sigMsg.Write(s.hello[:])
	sigMsg.Write(s.secHash)

	return ed25519.Verify(&s.remotePublic, sigMsg.Bytes(), &sig)
}

// cleanSecrets overwrites all intermediate secrets and copies the final secret to s.secret
func (s *State) cleanSecrets() {
	var zeros [64]byte

	copy(s.secHash, zeros[:])
	copy(s.secret[:], zeros[:]) // redundant
	copy(s.aBob[:], zeros[:])
	copy(s.bAlice[:], zeros[:])

	h := sha256.New()
	h.Write(s.secret3[:])
	copy(s.secret[:], h.Sum(nil))
	copy(s.secret2[:], zeros[:])
	copy(s.secret3[:], zeros[:])
	copy(s.localExchange.Secret[:], zeros[:])
}
