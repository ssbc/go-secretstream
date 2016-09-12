/*
This file is part of secretstream.

secretstream is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

secretstream is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with secretstream.  If not, see <http://www.gnu.org/licenses/>.
*/
package secretstream

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/cryptix/secretstream/secrethandshake"
)

// test interface fullfilment
var _ net.Listener = &Listener{nil, nil}

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
		var (
			c   net.Conn
			err error
		)
		c, err = l.Accept()
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
