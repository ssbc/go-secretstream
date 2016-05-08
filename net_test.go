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
	l, err := Listen("tcp", "localhost:0", *serverKeys, appKey)
	tcheck(t, err)

	go func() {
		c, err := l.Accept()
		tcheck(t, err)

		_, err = c.Write(appKey)
		tcheck(t, err)

		buf := make([]byte, len(appKey))
		_, err = io.ReadFull(c, buf)
		tcheck(t, err)

		if !bytes.Equal(buf, nappKey) {
			t.Fatal("server read wrong bytes")
		}

		c.Close()
		l.Close()
	}()

	client, err := Dial("tcp", l.Addr().String(), *clientKeys, appKey, serverKeys.Public)

	buf := make([]byte, len(appKey))
	_, err = io.ReadFull(client, buf)
	tcheck(t, err)
	if !bytes.Equal(buf, appKey) {
		t.Fatal("client read wrong bytes")
	}

	_, err = client.Write(nappKey)
	tcheck(t, err)

}
