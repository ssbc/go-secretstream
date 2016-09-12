/*
This file is part of secretstream.

secretstream is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

secretstream is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with secretstream.  If not, see <http://www.gnu.org/licenses/>.
*/
package secrethandshake

import (
	"io"
	"log"
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
