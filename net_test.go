// SPDX-License-Identifier: MIT

package secretstream

import (
	"bytes"
	"encoding/base64"
	"io"
	"math/rand"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/netwrap"
	"go.cryptoscope.co/secretstream/secrethandshake"
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

func TestNet(t *testing.T) {
	r := require.New(t)

	s, err := NewServer(*serverKeys, appKey)
	r.NoError(err)

	l, err := netwrap.Listen(&net.TCPAddr{IP: net.IP{127, 0, 0, 1}}, s.ListenerWrapper())
	r.NoError(err)

	testData := strings.Repeat("Hello, World!", 50)

	go func() {
		var (
			conn net.Conn
			err  error
		)
		conn, err = l.Accept()
		r.NoError(err)

		_, err = conn.Write(appKey)
		r.NoError(err)

		buf := make([]byte, len(testData))
		_, err = io.ReadFull(conn, buf)
		r.NoError(err)

		r.Equal(string(buf), testData, "server read wrong bytes")

		r.NoError(conn.Close())
		r.NoError(l.Close())
	}()

	c, err := NewClient(*clientKeys, appKey)
	r.NoError(err)

	tcpAddr := netwrap.GetAddr(l.Addr(), "tcp")
	connWrap := c.ConnWrapper(serverKeys.Public)

	conn, err := netwrap.Dial(tcpAddr, connWrap)
	r.NoError(err)

	buf := make([]byte, len(appKey))
	_, err = io.ReadFull(conn, buf)
	r.NoError(err)

	if !bytes.Equal(buf, appKey) {
		t.Fatalf("client read wrong bytes - expected %q, got %q", appKey, buf)
	}

	_, err = conn.Write([]byte(testData))
	r.NoError(err)

	r.NoError(conn.Close(), "failed to close conn")
}

func TestNetClose(t *testing.T) {
	r := require.New(t)

	s, err := NewServer(*serverKeys, appKey)
	r.NoError(err)

	l, err := netwrap.Listen(&net.TCPAddr{IP: net.IP{127, 0, 0, 1}}, s.ListenerWrapper())
	r.NoError(err)

	// 1 MiB
	testData := make([]byte, 1024*1024)
	for i, _ := range testData {
		testData[i] = byte(rand.Int() % 255)
	}

	done := make(chan struct{})
	go func() {
		var (
			c   net.Conn
			err error
		)
		c, err = l.Accept()
		r.NoError(err)

		_, err = c.Write(testData)
		r.NoError(err)
		// Immediately close conn after Write()

		<-done
		r.NoError(c.Close())
		r.NoError(l.Close())
	}()
	c, err := NewClient(*clientKeys, appKey)
	r.NoError(err)

	client, err := netwrap.Dial(netwrap.GetAddr(l.Addr(), "tcp"), c.ConnWrapper(serverKeys.Public))
	r.NoError(err)

	recData := make([]byte, 1024*1024)
	_, err = io.ReadFull(client, recData)
	r.NoError(err)
	r.Equal(recData, testData, "client read wrong bytes")
	close(done)

	r.NoError(client.Close(), "failed to close client")
}

// TODO add tests for incomplete boxes and see that the goroutine piping cleans up nicely

func TestNetCloseEarly(t *testing.T) {
	r := require.New(t)

	s, err := NewServer(*serverKeys, appKey)
	r.NoError(err)

	l, err := netwrap.Listen(&net.TCPAddr{IP: net.IP{127, 0, 0, 1}}, s.ListenerWrapper())
	r.NoError(err)

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
		r.NoError(err)

		// short write
		_, err = c.Write(testData[:10])
		r.NoError(err)

		r.NoError(c.Close())
		r.NoError(l.Close())
	}()
	c, err := NewClient(*clientKeys, appKey)
	r.NoError(err)

	client, err := netwrap.Dial(netwrap.GetAddr(l.Addr(), "tcp"), c.ConnWrapper(serverKeys.Public))
	r.NoError(err)

	recData := make([]byte, 1024*1024)
	_, err = io.ReadFull(client, recData)
	r.Error(err)

	err = client.Close()
	if err != nil {
		t.Error("failed to close client", err)
	}
}
