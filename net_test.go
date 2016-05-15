package secretstream

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/cryptix/secretstream/secrethandshake"
)

var (
	clientKeys, serverKeys *secrethandshake.EdKeyPair

	appKey []byte
)

func init() {
	var err error
	clientKeys, err = secrethandshake.GenEdKeyPair(nil)
	check(err)
	serverKeys, err = secrethandshake.GenEdKeyPair(nil)
	check(err)

	appKey, err = base64.StdEncoding.DecodeString("UjFLJ+aDSwKlaxxLBA3aWfL0pJDbrERwF1MWzQbeD0A=")
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func tcheck(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestNet(t *testing.T) {
	s, err := NewServer(*serverKeys, appKey)
	tcheck(t, err)

	l, err := s.Listen("tcp", "localhost:0")
	tcheck(t, err)

	testData := "Hello, World!"

	go func() {
		c, err := l.Accept()
		tcheck(t, err)

		_, err = c.Write(appKey)
		tcheck(t, err)

		buf := make([]byte, len(testData))
		_, err = io.ReadFull(c, buf)
		tcheck(t, err)

		if string(buf) != testData {
			t.Fatal("server read wrong bytes")
		}

		tcheck(t, c.Close())
		tcheck(t, l.Close())
	}()

	c, err := NewClient(*clientKeys, appKey)
	tcheck(t, err)

	dialer, err := c.NewDialer(serverKeys.Public)
	tcheck(t, err)

	client, err := dialer("tcp", l.Addr().String())
	tcheck(t, err)

	buf := make([]byte, len(appKey))
	_, err = io.ReadFull(client, buf)
	tcheck(t, err)
	if !bytes.Equal(buf, appKey) {
		t.Fatal("client read wrong bytes")
	}

	_, err = fmt.Fprintf(client, testData)
	tcheck(t, err)

}
