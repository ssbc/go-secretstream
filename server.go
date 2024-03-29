// SPDX-FileCopyrightText: 2021 The Secretstream Authors
//
// SPDX-License-Identifier: MIT

package secretstream

import (
	"fmt"
	"net"
	"time"

	"github.com/ssbc/go-secretstream/boxstream"
	"github.com/ssbc/go-secretstream/secrethandshake"

	"github.com/ssbc/go-netwrap"
)

// Server can create net.Listeners
type Server struct {
	keyPair secrethandshake.EdKeyPair
	appKey  []byte
}

// NewServer returns a Server which uses the passed keyPair and appKey
func NewServer(keyPair secrethandshake.EdKeyPair, appKey []byte) (*Server, error) {
	return &Server{keyPair: keyPair, appKey: appKey}, nil
}

// ListenerWrapper returns a listener wrapper.
func (s *Server) ListenerWrapper() netwrap.ListenerWrapper {
	return netwrap.NewListenerWrapper(s.Addr(), s.ConnWrapper())
}

// ConnWrapper returns a connection wrapper.
func (s *Server) ConnWrapper() netwrap.ConnWrapper {
	return func(conn net.Conn) (net.Conn, error) {
		state, err := secrethandshake.NewServerState(s.appKey, s.keyPair)
		if err != nil {
			return nil, err
		}

		if err != nil {
			return nil, err
		}

		errc := make(chan error)
		go func() {
			errc <- secrethandshake.Server(state, conn)
			close(errc)
		}()

		select {
		case err := <-errc:
			if err != nil {
				return nil, err
			}
		case <-time.After(2 * time.Minute):
			return nil, fmt.Errorf("secretstream: handshake timeout")
		}

		enKey, enNonce := state.GetBoxstreamEncKeys()
		deKey, deNonce := state.GetBoxstreamDecKeys()

		remote := state.Remote()
		boxed := &Conn{
			boxer:   boxstream.NewBoxer(conn, &enNonce, &enKey),
			unboxer: boxstream.NewUnboxer(conn, &deNonce, &deKey),
			conn:    conn,
			local:   s.keyPair.Public[:],
			remote:  remote[:],
		}

		return boxed, nil
	}
}

// Addr returns the shs-bs address of the server.
func (s *Server) Addr() net.Addr {
	return Addr{s.keyPair.Public[:]}
}
