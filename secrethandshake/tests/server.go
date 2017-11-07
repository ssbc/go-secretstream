// +build none

package main

import (
	"encoding/hex"
	"io"
	"os"

	"github.com/cryptix/go/logging"
	"github.com/cryptix/secretstream/secrethandshake"
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

	longtermSk, err := hex.DecodeString(os.Args[2])
	check(err)

	longtermPk, err := hex.DecodeString(os.Args[3])
	check(err)

	var keyPair secrethandshake.EdKeyPair

	copy(keyPair.Secret[:], longtermSk)
	copy(keyPair.Public[:], longtermPk)

	s, err := secrethandshake.NewServerState(appKey, keyPair)
	check(err)

	err = secrethandshake.Server(s, rw{os.Stdin, os.Stdout})
	check(err)

	// todo reply to msg4
}
