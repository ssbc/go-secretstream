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
	"math/rand"
	"net"
	"testing"

	"go.cryptoscope.co/secretstream/secrethandshake"

	"go.cryptoscope.co/netwrap"
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

	l, err := netwrap.Listen(&net.TCPAddr{IP: net.IP{127, 0, 0, 1}}, s.ListenerWrapper())
	tcheck(t, err)

	testData := "Hello, World!"

	go func() {
		var (
			conn net.Conn
			err  error
		)
		conn, err = l.Accept()
		tcheck(t, err)

		_, err = conn.Write(appKey)
		tcheck(t, err)

		buf := make([]byte, len(testData))
		_, err = io.ReadFull(conn, buf)
		tcheck(t, err)

		if string(buf) != testData {
			t.Fatal("server read wrong bytes")
		}

		tcheck(t, conn.Close())
		tcheck(t, l.Close())
	}()

	c, err := NewClient(*clientKeys, appKey)
	tcheck(t, err)

	tcpAddr := netwrap.GetAddr(l.Addr(), "tcp")
	connWrap := c.ConnWrapper(serverKeys.Public)

	conn, err := netwrap.Dial(tcpAddr, connWrap)
	tcheck(t, err)

	buf := make([]byte, len(appKey))
	_, err = io.ReadFull(conn, buf)
	tcheck(t, err)

	if !bytes.Equal(buf, appKey) {
		t.Fatalf("client read wrong bytes - expected %q, got %q", appKey, buf)
	}

	_, err = fmt.Fprintf(conn, testData)
	tcheck(t, err)

}

func TestNetClose(t *testing.T) {
	s, err := NewServer(*serverKeys, appKey)
	tcheck(t, err)

	l, err := netwrap.Listen(&net.TCPAddr{IP:net.IP{127,0,0,1}}, s.ListenerWrapper())
	tcheck(t, err)

	// 1 MiB
	testData := make([]byte, 1024*1024)
	for i, _ := range testData {
		testData[i] = byte(rand.Int() % 255)
	}

	go func() {
		var (
			c   net.Conn
			err error
		)
		c, err = l.Accept()
		tcheck(t, err)

		_, err = c.Write(testData)
		tcheck(t, err)
		// Immediately close conn after Write()

		tcheck(t, c.Close())
		tcheck(t, l.Close())
	}()
	c, err := NewClient(*clientKeys, appKey)
	tcheck(t, err)

	client, err := netwrap.Dial(netwrap.GetAddr(l.Addr(), "tcp"), c.ConnWrapper(serverKeys.Public))
	tcheck(t, err)

	recData := make([]byte, 1024*1024)
	_, err = io.ReadFull(client, recData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recData, testData) {
		t.Fatal("client read wrong bytes")
	}
}
