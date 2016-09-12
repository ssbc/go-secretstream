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
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/cryptix/go/logging/logtest"
	"github.com/cryptix/go/proc"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func mustLoadTestKeyPair(fname string) EdKeyPair {
	f, err := os.Open(fname)
	check(err)
	defer f.Close()

	var t struct {
		PublicKey, SecretKey string
	}
	check(json.NewDecoder(f).Decode(&t))

	pubClient, err := base64.StdEncoding.DecodeString(t.PublicKey)
	check(err)

	secSrv, err := base64.StdEncoding.DecodeString(t.SecretKey)
	check(err)

	var kp EdKeyPair
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
