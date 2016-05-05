package secretstream

import (
	"net"

	"github.com/agl/ed25519"
	"github.com/keks/shs"
)

func Dial(network, addr string, keyPair shs.EdKeyPair, appKey []byte, remotePub [ed25519.PublicKeySize]byte) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	return Client(conn, keyPair, appKey, remotePub)
}

type listener struct {
	l net.Listener

	keyPair shs.EdKeyPair
	appKey  []byte
}

func (l *listener) Addr() net.Addr {
	return Addr{l.Addr(), l.keyPair.Public[:]}
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.l.Accept()
	if err != nil {
		return nil, err
	}

	return ServerOnce(c, l.keyPair, l.appKey)
}

func (l *listener) Close() error {
	return l.Close()
}

func Listen(network, addr string, keyPair shs.EdKeyPair, appKey []byte) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	return &listener{l: l, keyPair: keyPair, appKey: appKey}, err
}
