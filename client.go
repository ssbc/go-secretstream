package secretstream

import (
	"net"

	"github.com/agl/ed25519"
	"github.com/cryptix/secretstream/boxstream"
	"github.com/cryptix/secretstream/secrethandshake"
)

// Client can dial secret-handshake server endpoints
type Client struct {
	appKey []byte
	kp     secrethandshake.EdKeyPair
}

// NewClient creates a new Client with the passed keyPair and appKey
func NewClient(kp secrethandshake.EdKeyPair, appKey []byte) (*Client, error) {
	// TODO: consistancy check?!..
	return &Client{
		appKey: appKey,
		kp:     kp,
	}, nil
}

// NewDialer returns a net.Dial-esque dialer that does a secrethandshake key exchange
// and wraps the underlying connection into a boxstream
func (c *Client) NewDialer(pubKey [ed25519.PublicKeySize]byte) (Dialer, error) {
	return func(n, a string) (net.Conn, error) {
		// TODO(cryptix): refuse non-tcp connections
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

		enKey, enNonce := state.GetBoxstreamEncKeys()
		deKey, deNonce := state.GetBoxstreamDecKeys()

		boxed := Conn{
			Reader: boxstream.NewUnboxer(conn, &deNonce, &deKey),
			Writer: boxstream.NewBoxer(conn, &enNonce, &enKey),
			conn:   conn,
			local:  c.kp.Public[:],
			remote: state.Remote(),
		}

		return boxed, nil
	}, nil
}
