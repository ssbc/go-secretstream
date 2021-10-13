// SPDX-FileCopyrightText: 2021 The Secretstream Authors
//
// SPDX-License-Identifier: MIT

// +build none

package main

import (
	"encoding/hex"
	"io"
	"os"

	"go.cryptoscope.co/secretstream/secrethandshake"
	"go.mindeco.de/logging"
)

var check = logging.CheckFatal

type rw struct {
	io.Reader
	io.Writer
}

func main() {
	//logging.SetupLogging(nil)
	//log := logging.Logger("goshs-test-server")

	appKey, err := hex.DecodeString(os.Args[1])
	check(err)

	var keyPair secrethandshake.EdKeyPair
	keyPair.Secret, err = hex.DecodeString(os.Args[2])
	check(err)

	keyPair.Public, err = hex.DecodeString(os.Args[3])
	check(err)

	s, err := secrethandshake.NewServerState(appKey, keyPair)
	check(err)

	err = secrethandshake.Server(s, rw{os.Stdin, os.Stdout})
	check(err)

	encKey, encNonce := s.GetBoxstreamEncKeys()
	os.Stdout.Write(encKey[:])
	os.Stdout.Write(encNonce[:])

	decKey, decNonnce := s.GetBoxstreamDecKeys()
	os.Stdout.Write(decKey[:])
	os.Stdout.Write(decNonnce[:])
}
