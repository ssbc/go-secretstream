// SPDX-FileCopyrightText: 2021 The Secretstream Authors
//
// SPDX-License-Identifier: MIT

package secretstream

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/ssbc/go-netwrap"
	"github.com/ssbc/go-secretstream/secrethandshake"
	"github.com/stretchr/testify/require"
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

func mkCheck(errc chan<- error) func(err error) {
	return func(err error) {
		if err != nil {
			errc <- err
		}
	}
}

func mergedErrors(cs ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	out := make(chan error, 1)

	output := func(c <-chan error) {
		for a := range c {
			out <- a
		}
		wg.Done()
	}

	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func TestNet(t *testing.T) {
	r := require.New(t)

	s, err := NewServer(*serverKeys, appKey)
	r.NoError(err)

	l, err := netwrap.Listen(&net.TCPAddr{IP: net.IP{127, 0, 0, 1}}, s.ListenerWrapper())
	r.NoError(err)

	testData := strings.Repeat("Hello, World!", 50)

	srvErrc := make(chan error)
	check := mkCheck(srvErrc)
	go func() {
		var (
			conn net.Conn
			err  error
		)
		conn, err = l.Accept()
		check(err)

		_, err = conn.Write(appKey)
		check(err)

		buf := make([]byte, len(testData))
		_, err = io.ReadFull(conn, buf)
		check(err)

		if string(buf) != testData {
			fmt.Errorf("server read wrong bytes: %x", buf)
			return
		}

		check(conn.Close())
		check(l.Close())
		close(srvErrc)
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

	i := 0
	for e := range srvErrc {
		r.NoError(e, "err %d from chan", i)
		i++
	}

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

	srvErrc := make(chan error)
	check := mkCheck(srvErrc)
	go func() {
		var (
			c   net.Conn
			err error
		)
		c, err = l.Accept()
		check(err)

		_, err = c.Write(testData)
		check(err)
		// Immediately close conn after Write()

		check(c.Close())
		check(l.Close())
		close(srvErrc)
	}()
	c, err := NewClient(*clientKeys, appKey)
	r.NoError(err)

	client, err := netwrap.Dial(netwrap.GetAddr(l.Addr(), "tcp"), c.ConnWrapper(serverKeys.Public))
	r.NoError(err)

	recData := make([]byte, 1024*1024)
	_, err = io.ReadFull(client, recData)
	r.NoError(err)
	r.Equal(recData, testData, "client read wrong bytes")

	r.NoError(client.Close(), "failed to close client")

	i := 0
	for e := range srvErrc {
		r.NoError(e, "err %d from chan", i)
		i++
	}
}

// a concurrent write might produce a race on the nonce
func TestRaceClose(t *testing.T) {
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

	srvErrc := make(chan error, 1)

	srving := make(chan net.Conn)
	go func() {
		check := mkCheck(srvErrc)
		c, err := l.Accept()
		check(err)

		// check(l.Close()) // one connection is enough
		srving <- c // give the conn to a _connection pool_

		// write one byte at a time, just to make this case more likely
		for b := bytes.NewBuffer(testData); b.Len() > 0; {
			_, err = c.Write(b.Next(1))
			if oerr, ok := err.(*net.OpError); ok {
				if oerr.Err.Error() == "use of closed network connection" {
					close(srvErrc)
					return
				}
			}
			check(err)
		}

		check(c.Close())
		close(srvErrc)
	}()

	// another part of the stack might decide to close it as it's being used
	closeErrc := make(chan error, 1)
	go func() {
		check := mkCheck(closeErrc)
		c := <-srving
		check(c.Close())
		close(closeErrc)
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

	i := 0
	for e := range mergedErrors(srvErrc, closeErrc) {
		r.NoError(e, "err %d from chan", i)
		i++
	}
}

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

	srvErrc := make(chan error)
	check := mkCheck(srvErrc)
	go func() {
		var (
			c   net.Conn
			err error
		)
		c, err = l.Accept()
		check(err)

		check(l.Close()) // one connection is enough

		// short write
		_, err = c.Write(testData[:10])
		check(err)

		check(c.Close())
		close(srvErrc)
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

	i := 0
	for e := range srvErrc {
		r.NoError(e, "err %d from chan", i)
		i++
	}
}
