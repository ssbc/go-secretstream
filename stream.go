package secretstream

import (
	"log"
	"net"

	"github.com/agl/ed25519"
	"github.com/cryptix/secretstream/secrethandshake"
	"github.com/keks/boxstream"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func Client(conn net.Conn, secretKey secrethandshake.EdKeyPair, appKey []byte, pubKey [ed25519.PublicKeySize]byte) (net.Conn, error) {
	state, err := secrethandshake.NewClientState(appKey, secretKey, pubKey)
	check(err)

	check(secrethandshake.Client(state, conn))

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
	check(err)

	err = secrethandshake.Server(state, conn)
	check(err)

	en_k, en_n := state.GetBoxstreamEncKeys()
	conn_w := boxstream.NewBoxer(conn, &en_n, &en_k)

	de_k, de_n := state.GetBoxstreamDecKeys()
	conn_r := boxstream.NewUnboxer(conn, &de_n, &de_k)

	remote := state.Remote()
	boxed := Conn{conn_r, conn_w, conn, secretKey.Public[:], remote[:]}

	return boxed, nil
}
