package secretstream

import (
	"net"

	"github.com/agl/ed25519"
	"github.com/cryptix/secretstream/boxstream"
	"github.com/cryptix/secretstream/secrethandshake"
)

func Client(conn net.Conn, secretKey secrethandshake.EdKeyPair, appKey []byte, pubKey [ed25519.PublicKeySize]byte) (net.Conn, error) {
	state, err := secrethandshake.NewClientState(appKey, secretKey, pubKey)
	if err != nil {
		return nil, err
	}

	if err := secrethandshake.Client(state, conn); err != nil {
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
