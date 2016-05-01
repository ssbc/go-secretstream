package shs

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cryptix/go/logging/logtest"
	"github.com/cryptix/go/proc"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func mustLoadKeyPair(fname string) KeyPair {
	f, err := os.Open(fname)
	check(err)

	var t struct {
		PublicKey, SecretKey string
	}
	check(json.NewDecoder(f).Decode(&t))

	pubClient, err := base64.StdEncoding.DecodeString(t.PublicKey)
	check(err)

	secSrv, err := base64.StdEncoding.DecodeString(t.SecretKey)
	check(err)

	var kp KeyPair
	copy(kp.Public[:], pubClient)
	copy(kp.Secret[:], secSrv)
	return kp
}

func TestClient(t *testing.T) {
	w := logtest.Logger("server_test.js", t)
	server, err := proc.StartStdioProcess("node", w, "server_test.js")
	if err != nil {
		t.Fatal(err)
	}

	go io.Copy(w, server)
	time.Sleep(2 * time.Second)

	appKey, err := base64.StdEncoding.DecodeString("IhrX11txvFiVzm+NurzHLCqUUe3xZXkPfODnp7WlMpk=")
	if err != nil {
		t.Fatal(err)
	}

	kpBob := mustLoadKeyPair("key.bob.json")
	kpAlice := mustLoadKeyPair("key.alice.json")

	clientState, err := NewClientState(appKey, kpAlice, kpBob.Public)
	if err != nil {
		t.Fatal("error making server state:", err)
	}

	conn, err := net.Dial("tcp", "localhost:8978")
	if err != nil {
		t.Fatal("error listening:", err)
	}

	if err := Client(*clientState, conn); err != nil {
		t.Fatal(err)
	}

	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}
