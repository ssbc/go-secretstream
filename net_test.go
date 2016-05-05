package secretstream

import (
	"bytes"
	"io"
	"testing"
)

func tcheck(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestNet(t *testing.T) {
	l, err := Listen("tcp", "localhost:19099", serverKeys, appKey)
	tcheck(t, err)

	go func() {
		c, err := l.Accept()
		tcheck(t, err)

		_, err = c.Write(appKey)
		if err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, len(appKey))
		_, err = io.ReadFull(c, buf)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(buf, nappKey) {
			t.Fatal("server read wrong bytes")
		}

		c.Close()
		l.Close()
	}()

	client, err := Dial("tcp", "localhost:19099", clientKeys, appKey, serverKeys.Public)
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
