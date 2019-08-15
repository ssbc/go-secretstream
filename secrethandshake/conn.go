// SPDX-License-Identifier: MIT

package secrethandshake

import (
	"crypto/rand"
	"fmt"
	"io"

	"go.cryptoscope.co/secretstream/internal/lo25519"

	"github.com/agl/ed25519"
	"github.com/pkg/errors"
)

type ErrProtocol struct {
	code int
}

func (eh ErrProtocol) Error() string {
	switch eh.code {
	case 0:
		return "secrethandshake: Wrong protocol version?"
	case 1:
		return "secrethandshake: other side not authenticated"
	default:
		return fmt.Sprintf("shs: unhandled error %d", eh)
	}
}

// ChallengeLength is the length of a challenge message in bytes
const ChallengeLength = 64

// ClientAuthLength is the length of a clientAuth message in bytes
const ClientAuthLength = 16 + 32 + 64

// ServerAuthLength is the length of a serverAuth message in bytes
const ServerAuthLength = 16 + 64

// MACLength is the length of a MAC in bytes
const MACLength = 16

// GenEdKeyPair generates a ed25519 keyPair using the passed reader
// if r == nil it uses crypto/rand.Reader
func GenEdKeyPair(r io.Reader) (*EdKeyPair, error) {
	if r == nil {
		r = rand.Reader
	}
	pubSrv, secSrv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	if lo25519.IsEdLowOrder(pubSrv[:]) {
		pubSrv, secSrv, err = ed25519.GenerateKey(r)
	}
	return &EdKeyPair{*pubSrv, *secSrv}, err
}

// Client shakes hands using the cryptographic identity specified in s using conn in the client role
func Client(state *State, conn io.ReadWriter) (err error) {
	// send challenge
	_, err = conn.Write(state.createChallenge())
	if err != nil {
		return errors.Wrapf(err, "secrethandshake: sending challenge failed.")
	}

	// recv challenge
	chalResp := make([]byte, ChallengeLength)
	_, err = io.ReadFull(conn, chalResp)
	if err != nil {
		return errors.Wrapf(err, "secrethandshake: receiving challenge failed.")
	}

	// verify challenge
	if !state.verifyChallenge(chalResp) {
		return ErrProtocol{0}
	}

	// send authentication vector
	_, err = conn.Write(state.createClientAuth())
	if err != nil {
		return errors.Wrapf(err, "secrethandshake: sending client auth failed.")
	}

	// recv authentication vector
	boxedSig := make([]byte, ServerAuthLength)
	_, err = io.ReadFull(conn, boxedSig)
	if err != nil {
		return errors.Wrapf(err, "secrethandshake: receiving server auth failed")
	}

	// authenticate remote
	if !state.verifyServerAccept(boxedSig) {
		return ErrProtocol{1}
	}

	state.cleanSecrets()
	return nil
}

// Server shakes hands using the cryptographic identity specified in s using conn in the server role
func Server(state *State, conn io.ReadWriter) (err error) {
	// recv challenge
	challenge := make([]byte, ChallengeLength)
	_, err = io.ReadFull(conn, challenge)
	if err != nil {
		return errors.Wrapf(err, "secrethandshake: receiving challenge failed")
	}

	// verify challenge
	if !state.verifyChallenge(challenge) {
		return ErrProtocol{0}
	}

	// send challenge
	_, err = conn.Write(state.createChallenge())
	if err != nil {
		return errors.Wrapf(err, "secrethandshake: sending server challenge failed.")
	}

	// recv authentication vector
	hello := make([]byte, ClientAuthLength)
	_, err = io.ReadFull(conn, hello)
	if err != nil {
		return errors.Wrapf(err, "secrethandshake: receiving client hello failed")
	}

	// authenticate remote
	if !state.verifyClientAuth(hello) {
		return ErrProtocol{1}
	}

	// accept
	_, err = conn.Write(state.createServerAccept())
	if err != nil {
		return errors.Wrapf(err, "secrethandshake: sending server auth accept failed.")
	}

	state.cleanSecrets()
	return nil
}
