package secretstream

import (
	"net"

	"github.com/agl/ed25519"
	"github.com/cryptix/secretstream/boxstream"
	"github.com/cryptix/secretstream/secrethandshake"
)

type Client struct {
	appKey []byte
	kp     secrethandshake.EdKeyPair
}

func NewClient(kp secrethandshake.EdKeyPair, appKey []byte) (*Client, error) {
	// TODO: consistancy check?!..
	return &Client{
		appKey: appKey,
		kp:     kp,
	}, nil
}

func (c *Client) NewDialer(pubKey [ed25519.PublicKeySize]byte) (Dialer, error) {
	return func(n, a string) (net.Conn, error) {
		conn, err := net.Dial(n, a)
		if err != nil {
			return nil, err
		}
		state, err := secrethandshake.NewClientState(c.appKey, c.kp, pubKey)
		if err != nil {
			return nil, err
		}

		if err := secrethandshake.Client(state, conn); err != nil {
			return nil, err
		}

		en_k, en_n := state.GetBoxstreamEncKeys()
		de_k, de_n := state.GetBoxstreamDecKeys()

		boxed := Conn{
			Reader: boxstream.NewUnboxer(conn, &de_n, &de_k),
			Writer: boxstream.NewBoxer(conn, &en_n, &en_k),
			conn:   conn,
			local:  c.kp.Public[:],
			remote: state.Remote(),
		}

		return boxed, nil
	}, nil
}
