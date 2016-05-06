package secretstream

import (
	"net"

	"github.com/agl/ed25519"
	"github.com/cryptix/secretstream/secrethandshake"
)

func Dial(network, addr string, keyPair secrethandshake.EdKeyPair, appKey []byte, remotePub [ed25519.PublicKeySize]byte) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	return Client(conn, keyPair, appKey, remotePub)
}

type listener struct {
	net.Listener

	keyPair secrethandshake.EdKeyPair
	appKey  []byte
}

func (l *listener) Addr() net.Addr {
	return Addr{l.Listener.Addr(), l.keyPair.Public[:]}
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return ServerOnce(c, l.keyPair, l.appKey)
}

func Listen(network, addr string, keyPair secrethandshake.EdKeyPair, appKey []byte) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	return &listener{Listener: l, keyPair: keyPair, appKey: appKey}, err
}
