package secretstream

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"github.com/keks/shs"
)

var (
	clientKeys, serverKeys shs.EdKeyPair

	clientSec, _ = base64.StdEncoding.DecodeString("Ws5HDF3Mj0H21PZx0TRjmfi59Fp/rynyELlXqjFwtbU=")
	serverSec, _ = base64.StdEncoding.DecodeString("Xh2j3RVNpG6VEn7eoxhjrD/ksfI9Ddn4KR3ws6kIrGc=")
	appKey, _    = base64.StdEncoding.DecodeString("UjFLJ+aDSwKlaxxLBA3aWfL0pJDbrERwF1MWzQbeD0A=")
	nappKey      = make([]byte, len(appKey))
)

func init() {
	clientKeys, _ = shs.GenEdKeyPair(bytes.NewBuffer(clientSec))
	serverKeys, _ = shs.GenEdKeyPair(bytes.NewBuffer(serverSec))

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
		server, err := ServerOnce(serverconn, serverKeys, appKey)
		if err != nil {
			t.Fatal(err)
		}

		_, err = server.Write(appKey)
		if err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, len(appKey))
		_, err = io.ReadFull(server, buf)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(buf, nappKey) {
			t.Fatal("server read wrong bytes")
		}
	}()

	client, err := Client(clientConn, clientKeys, appKey, serverKeys.Public)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(appKey))
	_, err = io.ReadFull(client, buf)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf, appKey) {
		t.Fatal("client read wrong bytes")
	}

	_, err = client.Write(nappKey)
	if err != nil {
		t.Fatal(err)
	}
}
