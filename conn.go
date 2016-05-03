package shs

import (
	"errors"
	"fmt"
	"io"
	"log"
)

// ChallengeLength is the length of a challenge message in bytes
const ChallengeLength = 64

// ClientAuthLength is the length of a clientAuth message in bytes
const ClientAuthLength = 16 + 32 + 64

// ServerAuthLength is the length of a serverAuth message in bytes
const ServerAuthLength = 16 + 64

// MACLength is the length of a MAC in bytes
const MACLength = 16

// Client shakes hands using the cryptographic identity specified in s using conn in the client role
func Client(state *State, conn io.ReadWriter) (err error) {
	var n int
	/*
		defer func() {
			log.Println("client: returned", err)
		}()
	*/

	// send challenge
	n, err = conn.Write(state.createChallenge())
	if err != nil {
		return err
	}
	if n != ChallengeLength {
		return errors.New("wrong challenge length")
	}

	log.Println("client: challenge sent")

	// recv challenge
	chalResp := make([]byte, ChallengeLength)
	_, err = io.ReadFull(conn, chalResp)
	if err != nil {
		return err
	}

	log.Println("client: challenge received")

	// verify challenge
	if !state.verifyChallenge(chalResp) {
		return errors.New("Wrong protocol version?")
	}

	log.Println("client: challenge verified")

	//log.Printf("client:\n%v\n", &state)
	// send authentication vector

	n, err = conn.Write(state.createClientAuth())
	if err != nil {
		return err
	}
	if n != ClientAuthLength {
		return errors.New("wrong client auth length")
	}

	log.Println("client: auth vector sent. len:", n)

	// recv authentication vector
	boxedSig := make([]byte, ServerAuthLength)
	n, err = io.ReadFull(conn, boxedSig)
	if err != nil {
		log.Println("client: couln't read server accept. read len", n)
		return err
	}

	log.Println("client: auth vector received")

	// authenticate remote
	if !state.verifyServerAccept(boxedSig) {
		return errors.New("server not authenticated")
	}

	log.Println("client: remote authenticated")

	state.cleanSecrets()
	log.Println("client: secrets cleaned. returning")
	return nil
}

// Server shakes hands using the cryptographic identity specified in s using conn in the server role
func Server(state *State, conn io.ReadWriter) (err error) {
	var n int
	defer func() {
		log.Println("server: returned", err)
	}()

	// recv challenge
	challenge := make([]byte, ChallengeLength)
	_, err = io.ReadFull(conn, challenge)
	if err != nil {
		return err
	}

	log.Println("server: challenge received")

	// verify challenge
	if !state.verifyChallenge(challenge) {
		return errors.New("Wrong protocol version?")
	}

	log.Println("server: challenge verified")
	//log.Printf("server:\n%v\n", &state)

	// send challenge
	n, err = conn.Write(state.createChallenge())
	if err != nil {
		return err
	}
	if n != ChallengeLength {
		return errors.New("wrong server challenge length")
	}

	log.Println("server: challenge sent")

	// recv authentication vector
	hello := make([]byte, ClientAuthLength)
	_, err = io.ReadFull(conn, hello)
	if err != nil {
		return err
	}

	log.Println("server: auth vector received")

	// authenticate remote
	if !state.verifyClientAuth(hello) {
		return errors.New("client not authenticated")
	}

	log.Println("server: remote authenticated")

	// accept
	n, err = conn.Write(state.createServerAccept())
	if err != nil {
		return err
	}
	if n != ServerAuthLength {
		return fmt.Errorf("wrong server auth length: %v", n)
	}

	log.Println("server: accept sent")

	state.cleanSecrets()
	log.Println("server: secrets cleaned. returning")

	return nil
}
