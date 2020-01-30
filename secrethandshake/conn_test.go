// SPDX-License-Identifier: MIT

package secrethandshake

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

// StupidRandom always reads itself. Goal is determinism.
type StupidRandom byte

// Read reads from the stupid random source
func (sr StupidRandom) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = byte(sr)
	}

	return len(buf), nil
}

// rw implements io.ReadWriter using an io.Reader and io.Writer
type rw struct {
	io.Reader
	io.Writer
}

// TestAuth is an integration test
func TestAuth(t *testing.T) {
	log.SetOutput(os.Stdout)

	keySrv, err := GenEdKeyPair(StupidRandom(0))
	if err != nil {
		t.Fatal(err)
	}

	keyClient, err := GenEdKeyPair(StupidRandom(1))
	if err != nil {
		t.Fatal(err)
	}

	appKey := make([]byte, 32)
	io.ReadFull(StupidRandom(255), appKey)

	rServer, wClient := io.Pipe()
	rClient, wServer := io.Pipe()

	rwServer := rw{rServer, wServer}
	rwClient := rw{rClient, wClient}

	serverState, err := NewServerState(appKey, *keySrv)
	if err != nil {
		t.Error("error making server state:", err)
	}

	clientState, err := NewClientState(appKey, *keyClient, keySrv.Public)
	if err != nil {
		t.Error("error making client state:", err)
	}

	// buffered channel
	ch := make(chan error, 2)

	go func() {
		err := Server(serverState, rwServer)
		ch <- err
		wServer.Close()
	}()

	go func() {
		err := Client(clientState, rwClient)
		ch <- err
		wClient.Close()
	}()

	// t.Error may only be called from this goroutine :/
	if err = <-ch; err != nil {
		t.Error(err)
	}
	if err = <-ch; err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(clientState.secret, serverState.secret) {
		t.Error("secrets not equal")
	}
}

func TestAuthWrong(t *testing.T) {
	log.SetOutput(os.Stdout)

	keySrv, err := GenEdKeyPair(StupidRandom(0))
	if err != nil {
		t.Fatal(err)
	}

	keyClient, err := GenEdKeyPair(StupidRandom(1))
	if err != nil {
		t.Fatal(err)
	}

	appKey := make([]byte, 32)
	io.ReadFull(StupidRandom(255), appKey)

	rServer, wClient := io.Pipe()
	rClient, wServer := io.Pipe()

	rwServer := rw{rServer, wServer}
	rwClient := rw{rClient, wClient}

	serverState, err := NewServerState(appKey, *keySrv)
	if err != nil {
		t.Error("error making server state:", err)
	}

	clientState, err := NewClientState(appKey, *keyClient, keySrv.Public)
	if err != nil {
		t.Error("error making client state:", err)
	}

	// buffered channel
	ch := make(chan error, 2)

	go func() {
		err := Server(serverState, rwServer)
		expErr := ErrProtocol{1}
		if err != expErr {
			ch <- fmt.Errorf("server failed differntly then expected: %w", err)
		} else {
			ch <- nil
		}
		wServer.Close()
	}()

	go func() {
		err := wrongClient(clientState, rwClient)
		ch <- fmt.Errorf("client failed: %w", err)
		wClient.Close()
	}()

	// t.Error may only be called from this goroutine :/
	if err = <-ch; err != nil {
		t.Error(err)
	}
	if err = <-ch; err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(clientState.secret, serverState.secret) {
		t.Error("secrets not equal")
	}
}

// wrong client is a version of Client() that messes up the client auth and expects the connection to be shut down afterwards
func wrongClient(state *State, conn io.ReadWriter) (err error) {
	_, err = io.Copy(conn, bytes.NewReader(state.createChallenge()))
	if err != nil {
		return fmt.Errorf("secrethandshake: sending challenge failed. %w", err)
	}

	// recv challenge
	chalResp := make([]byte, ChallengeLength)
	_, err = io.ReadFull(conn, chalResp)
	if err != nil {
		return fmt.Errorf("secrethandshake: receiving challenge failed. %w", err)
	}

	// verify challenge
	if !state.verifyChallenge(chalResp) {
		return errors.New("secrethandshake: challenge didn't verify")
	}

	// prepare authentication vector
	cauth := state.createClientAuth()

	// flip two bytes
	n := len(cauth) - 1
	i := rand.Intn(n)
	if i == n {
		i = n - 1
	}
	cauth[i], cauth[n] = cauth[n], cauth[i]

	_, err = io.Copy(conn, bytes.NewReader(cauth))
	if err != nil {
		return fmt.Errorf(err, "secrethandshake: sending client auth failed. %w", err)
	}

	// recv authentication vector? shouldn't get it
	boxedSig := make([]byte, ServerAuthLength)
	n, err = io.ReadFull(conn, boxedSig)
	if err != io.EOF || n != 0 {
		return fmt.Errorf("wrongClient: expected unepexcted EOF, got %d bytes and err: %w", n, err)
	}

	return nil
}
