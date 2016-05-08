package secretstream

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"github.com/cryptix/secretstream/secrethandshake"
)

var (
	clientKeys, serverKeys *secrethandshake.EdKeyPair

	clientSec, _ = base64.StdEncoding.DecodeString("Ws5HDF3Mj0H21PZx0TRjmfi59Fp/rynyELlXqjFwtbU=")
	serverSec, _ = base64.StdEncoding.DecodeString("Xh2j3RVNpG6VEn7eoxhjrD/ksfI9Ddn4KR3ws6kIrGc=")
	appKey, _    = base64.StdEncoding.DecodeString("UjFLJ+aDSwKlaxxLBA3aWfL0pJDbrERwF1MWzQbeD0A=")
	nappKey      = make([]byte, len(appKey))
)

func init() {
	clientKeys, _ = secrethandshake.GenEdKeyPair(bytes.NewReader(clientSec))
	serverKeys, _ = secrethandshake.GenEdKeyPair(bytes.NewReader(serverSec))

	for i := range appKey {
		nappKey[i] = ^appKey[i]
	}
}

func TestConn(t *testing.T) {
	prBack, pwBack := io.Pipe()
	prForth, pwForth := io.Pipe()

	serverconn := Conn{Reader: prBack, Writer: pwForth, conn: &noConn{}}
	clientConn := Conn{Writer: pwBack, Reader: prForth, conn: &noConn{}}

	go func() {
		server, err := ServerOnce(serverconn, *serverKeys, appKey)
		tcheck(t, err)

		_, err = server.Write(appKey)
		tcheck(t, err)

		buf := make([]byte, len(appKey))
		_, err = io.ReadFull(server, buf)
		tcheck(t, err)

		if !bytes.Equal(buf, nappKey) {
			t.Fatal("server read wrong bytes")
		}
	}()

	client, err := Client(clientConn, *clientKeys, appKey, serverKeys.Public)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(appKey))
	_, err = io.ReadFull(client, buf)
	tcheck(t, err)

	if !bytes.Equal(buf, appKey) {
		t.Fatal("client read wrong bytes")
	}

	_, err = client.Write(nappKey)
	tcheck(t, err)
}
