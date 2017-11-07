package main

import (
	"encoding/hex"
	"io"
	"os"

	"github.com/agl/ed25519"
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
	//log := logging.Logger("goshs-test-client")

	appKey, err := hex.DecodeString(os.Args[1])
	check(err)

	serverPkbytes, err := hex.DecodeString(os.Args[2])
	check(err)
	var remotePublic [ed25519.PublicKeySize]byte
	copy(remotePublic[:], serverPkbytes)

	keyPair, err := secrethandshake.GenEdKeyPair(nil)
	check(err)

	s, err := secrethandshake.NewClientState(appKey, *keyPair, remotePublic)
	check(err)

	err = secrethandshake.Client(s, rw{os.Stdin, os.Stdout})
	check(err)

	// todo reply to msg4
}
