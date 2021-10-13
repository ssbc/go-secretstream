// SPDX-FileCopyrightText: 2021 The Secretstream Authors
//
// SPDX-License-Identifier: MIT

//go:build interop_nodejs
// +build interop_nodejs

package secrethandshake

import (
	"encoding/base64"
	"testing"

	"go.mindeco.de/logging/logtest"
	"go.mindeco.de/proc"
)

func TestServer(t *testing.T) {
	var err error

	var kp EdKeyPair
	kp.Public, err = base64.StdEncoding.DecodeString("dz9tpZBrNTCCKiA+mIn/x1M6IEO9k05DbkgpqsGbTpE=")
	if err != nil {
		t.Fatal(err)
	}

	kp.Secret, err = base64.StdEncoding.DecodeString("kB4WbT+KvUYwpCxc0FC5+FYKFbUFMoIR+f7VhDVWvU13P22lkGs1MIIqID6Yif/HUzogQ72TTkNuSCmqwZtOkQ==")
	if err != nil {
		t.Fatal(err)
	}

	appKey, err := base64.StdEncoding.DecodeString("IhrX11txvFiVzm+NurzHLCqUUe3xZXkPfODnp7WlMpk=")
	if err != nil {
		t.Fatal(err)
	}

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
