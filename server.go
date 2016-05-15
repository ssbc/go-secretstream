package secretstream

import (
	"net"

	"github.com/cryptix/secretstream/boxstream"
	"github.com/cryptix/secretstream/secrethandshake"
)

type Server struct {
	keyPair secrethandshake.EdKeyPair
	appKey  []byte
}

func NewServer(keyPair secrethandshake.EdKeyPair, appKey []byte) (*Server, error) {
	return &Server{keyPair: keyPair, appKey: appKey}, nil
}

func (s Server) Listen(n, a string) (net.Listener, error) {
	l, err := net.Listen(n, a)
	if err != nil {
		return nil, err
	}

	return &Listener{l: l, s: &s}, nil
}

func ServerOnce(conn net.Conn, secretKey secrethandshake.EdKeyPair, appKey []byte) (net.Conn, error) {
	state, err := secrethandshake.NewServerState(appKey, secretKey)
	if err != nil {
		return nil, err
	}

	err = secrethandshake.Server(state, conn)
	if err != nil {
		return nil, err
	}
	en_k, en_n := state.GetBoxstreamEncKeys()
	conn_w := boxstream.NewBoxer(conn, &en_n, &en_k)

	de_k, de_n := state.GetBoxstreamDecKeys()
	conn_r := boxstream.NewUnboxer(conn, &de_n, &de_k)

	remote := state.Remote()
	boxed := Conn{conn_r, conn_w, conn, secretKey.Public[:], remote[:]}

	return boxed, nil
}
