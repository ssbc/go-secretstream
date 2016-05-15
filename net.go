package secretstream

import "net"

type Dialer func(net, addr string) (net.Conn, error)

type Listener struct {
	l net.Listener
	s *Server
}

var _ net.Listener = Listener{}

func (l Listener) Addr() net.Addr {
	return Addr{l.l.Addr(), l.s.keyPair.Public[:]}
}

func (l Listener) Close() error {
	return l.l.Close()
}

func (l Listener) Accept() (net.Conn, error) {
	c, err := l.l.Accept()
	if err != nil {
		return nil, err
	}

	return ServerOnce(c, l.s.keyPair, l.s.appKey)
}
