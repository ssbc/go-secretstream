// SPDX-License-Identifier: MIT

package secrethandshake

import (
	"io"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/pkg/errors"
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
		ch <- errors.Wrap(err, "server failed")
		wServer.Close()
	}()

	go func() {
		err := Client(clientState, rwClient)
		ch <- errors.Wrap(err, "client failed")
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
