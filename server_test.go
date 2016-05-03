package shs

import (
	"encoding/base64"
	"testing"

	"github.com/cryptix/go/logging/logtest"
	"github.com/cryptix/go/proc"
)

func TestServer(t *testing.T) {

	pubServ, err := base64.StdEncoding.DecodeString("dz9tpZBrNTCCKiA+mIn/x1M6IEO9k05DbkgpqsGbTpE=")
	if err != nil {
		t.Fatal(err)
	}

	secSrv, err := base64.StdEncoding.DecodeString("kB4WbT+KvUYwpCxc0FC5+FYKFbUFMoIR+f7VhDVWvU13P22lkGs1MIIqID6Yif/HUzogQ72TTkNuSCmqwZtOkQ==")
	if err != nil {
		t.Fatal(err)
	}

	appKey, err := base64.StdEncoding.DecodeString("IhrX11txvFiVzm+NurzHLCqUUe3xZXkPfODnp7WlMpk=")
	if err != nil {
		t.Fatal(err)
	}

	var kp EdKeyPair
	copy(kp.Public[:], pubServ)
	copy(kp.Secret[:], secSrv)

	serverState, err := NewServerState(appKey, kp)
	if err != nil {
		t.Fatal("error making server state:", err)
	}

	client, err := proc.StartStdioProcess("node", logtest.Logger("client_test.js", t), "client_test.js")
	if err != nil {
		t.Fatal(err)
	}

	if err := Server(serverState, client); err != nil {
		t.Fatal(err)
	}

}
