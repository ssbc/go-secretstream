package shs

import (
	"io"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/agl/ed25519"
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

	pubSrv, secSrv, err := ed25519.GenerateKey(StupidRandom(0))
	if err != nil {
		panic(err)
	}

	pubCli, secCli, err := ed25519.GenerateKey(StupidRandom(1))
	if err != nil {
		panic(err)
	}

	appKey := make([]byte, 32)
	io.ReadFull(StupidRandom(255), appKey)

	rServer, wClient := io.Pipe()
	rClient, wServer := io.Pipe()

	rwServer := rw{rServer, wServer}
	rwClient := rw{rClient, wClient}

	serverState, err := NewServerState(appKey, KeyPair{*pubSrv, *secSrv})
	if err != nil {
		t.Error("error making server state:", err)
	}

	clientState, err := NewClientState(appKey, KeyPair{*pubCli, *secCli}, *pubSrv)
	if err != nil {
		t.Error("error making client state:", err)
	}

	// buffered channel
	ch := make(chan error, 2)

	go func() {
		err := Server(*serverState, rwServer)
		ch <- err
		wServer.Close()
	}()

	go func() {
		err := Client(*clientState, rwClient)
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
