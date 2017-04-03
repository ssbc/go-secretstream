package stateless

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"log"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/pkg/errors"
)

// EdKeyPair is a keypair for use with github.com/agl/ed25519
type EdKeyPair struct {
	Public [ed25519.PublicKeySize]byte
	Secret [ed25519.PrivateKeySize]byte
}

// CurveKeyPair is a keypair for use with curve25519
type CurveKeyPair struct {
	Public [32]byte
	Secret [32]byte
}

type State struct {
	appKey       []byte
	ephKeyPair   CurveKeyPair
	local        EdKeyPair
	remotePublic [ed25519.PublicKeySize]byte

	localAppMac []byte

	/* TODO: test only data
	there might be a funky conditional compilation dance
	to only include these fields in the test package
	but first make the tests pass.
	*/
	ephRand    io.Reader
	ephRandBuf bytes.Buffer // stores the bytes we read
}

type Option func(s *State) error

func SetAppKey(ak string) Option {
	return func(s *State) error {
		var err error
		s.appKey, err = hex.DecodeString(ak)
		if err != nil {
			return errors.Wrapf(err, "SetAppKey(): failed to decode %q", ak)
		}
		return nil
	}
}

func LocalKey(kp EdKeyPair) Option {
	return func(s *State) error {
		s.local = kp
		return nil
	}
}

// LocalKeyFromSeed is only used for testing against known values
func LocalKeyFromSeed(r io.Reader) Option {
	return func(s *State) error {
		pk, sk, err := ed25519.GenerateKey(r)
		copy(s.local.Public[:], pk[:])
		copy(s.local.Secret[:], sk[:])
		return err
	}
}

func LocalKeyFromHex(public, secret string) Option {
	return func(s *State) error {
		pk, err := hex.DecodeString(public)
		if err != nil {
			return errors.Wrap(err, "LocalKeyFromHex(): failed to decode public key")
		}
		sk, err := hex.DecodeString(secret)
		if err != nil {
			return errors.Wrap(err, "LocalKeyFromHex(): failed to decode secret key")
		}
		copy(s.local.Public[:], pk[:])
		copy(s.local.Secret[:], sk[:])
		return err
	}
}

// EphemeralRand is only used for testing against known values
func EphemeralRand(r io.Reader) Option {
	return func(s *State) error {
		log.Println("setting determ. rand")
		s.ephRand = r
		return nil
	}
}

// EphemeralRandFromHex is only used for testing against known values
func EphemeralRandFromHex(rand string) Option {
	return func(s *State) error {
		rbytes, err := hex.DecodeString(rand)
		if err != nil {
			return errors.Wrap(err, "EphemeralRandFromHex(): failed to decode rand bytes")
		}
		s.ephRand = io.TeeReader(bytes.NewReader(rbytes), &s.ephRandBuf)
		return nil
	}
}

func RemotePubFromHex(pub string) Option {
	return func(s *State) error {
		b, err := hex.DecodeString(pub)
		copy(s.remotePublic[:], b)
		return err
	}
}

func Initialize(opts ...Option) (*State, error) {
	s := new(State)

	for i, o := range opts {
		if err := o(s); err != nil {
			return nil, errors.Wrapf(err, "Initialize(): failed to use option %d", i)
		}
	}

	// TODO: check that all needed info is present
	if len(s.appKey) != 32 {
		return nil, errors.New("Initialize(): appKey needed")
	}

	if s.ephRand == nil {
		log.Println("using crypto/rand")
		s.ephRand = rand.Reader
	}

	pubKey, secKey, err := ed25519.GenerateKey(s.ephRand)
	if err != nil {
		return nil, errors.Wrap(err, "Initialize(): failed to generate ephemeral key")
	}
	if !extra25519.PublicKeyToCurve25519(&s.ephKeyPair.Public, pubKey) {
		return nil, errors.New("Initialize(): could not curvify pubkey")
	}
	extra25519.PrivateKeyToCurve25519(&s.ephKeyPair.Secret, secKey)

	appMacr := hmac.New(sha512.New, s.appKey[:32])
	appMacr.Write(s.ephKeyPair.Public[:])
	s.localAppMac = appMacr.Sum(nil)[:32]

	return s, nil
}
