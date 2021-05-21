// +build interop_nodejs

// SPDX-License-Identifier: MIT

package secrethandshake

import (
	"encoding/base64"
	"testing"

	"go.mindeco.de/logging/logtest"
	"go.mindeco.de/proc"
)

func TestClient(t *testing.T) {
	w := logtest.Logger("server_test.js", t)
	server, err := proc.StartStdioProcess("node", w, "server_test.js")
	if err != nil {
		t.Fatal(err)
	}

	appKey, err := base64.StdEncoding.DecodeString("IhrX11txvFiVzm+NurzHLCqUUe3xZXkPfODnp7WlMpk=")
	if err != nil {
		t.Fatal(err)
	}

	kpBob := mustLoadTestKeyPair("key.bob.json")
	kpAlice := mustLoadTestKeyPair("key.alice.json")

	clientState, err := NewClientState(appKey, kpAlice, kpBob.Public)
	if err != nil {
		t.Fatal("error making server state:", err)
	}

	if err := Client(clientState, server); err != nil {
		t.Fatal(err)
	}

	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}
