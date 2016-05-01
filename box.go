package boxstream

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
)

const (
	HeaderLength   = 2 + 16 + 16
	MaxSegmentSize = 4 * 1024
)

var (
	WrongKeyLength   = fmt.Errorf("wrong key length")
	WrongNonceLength = fmt.Errorf("wrong nonce length")
)

type Boxer struct {
	w             io.Writer
	secret, nonce []byte
}

type Unboxer struct {
	r             io.Reader
	secret, nonce []byte
}

func NewBoxer(w io.Writer, secret, nonce []byte) (io.Writer, error) {
	if len(secret) != 32 {
		return nil, WrongKeyLength
	}

	if len(nonce) != 24 {
		return nil, WrongNonceLength
	}

	return &Boxer{w: w, secret: secret, nonce: nonce}, nil
}

func NewUnboxer(r io.Reader, secret, nonce []byte) (io.Reader, error) {
	if len(secret) != 32 {
		return nil, WrongKeyLength
	}

	if len(nonce) != 24 {
		return nil, WrongNonceLength
	}

	return &Boxer{r: r, secret: secret, nonce: nonce}, nil
}

func increment(b []byte) []byte {
	var i int
	for i = len(b) - 1; i >= 0 && b[i] == 0xff; i-- {
		b[i] = 0
	}

	if i < 0 {
		return b
	}

	b[i] = b[i] + 1

	return b
}

func (u *Unboxer) readerloop(buf []byte) (int, error) {
	hdrBox := make([]byte, HeaderLength)

	err := io.ReadFull(u.r, hdrBox)
	if err != nil {
		return 0, err
	}

	hdr := make([]byte, 0, HeaderLength-secretbox.Overhead)
	hdr, ok = secretbox.Open(hdr, hdrBox, increment(b.nonce), b.key)
	if !ok {
		return 0, fmt.Errorf("error opening header box")
	}

	n := binary.LitteEndian.Uint16(hdr[:2])

	buf := make([]byte, n)

	tag := hdr[2:]
	copy(buf[:16], tag)

	err = io.ReadFull(u.r, buf[len(tag)])
	if err != nil {
		return 0, err
	}

	out := make([]byte, 0, n)
	out, ok = secretbox.Open(out, buf, increment(b.nonce), b.key)
	if !ok {
		return 0, fmt.Errorf("error opening body box")
	}

	return 0, fmt.Errorf("not implemented")
}

func (b *Boxer) Write(buf []byte) (int, error) {
	// segment large writes
	for len(buf > MaxSegmentSize) {
		// fetch current segment
		current = buf[:MaxSegmentSize]
		buf = buf[MaxSegmentSize:]

		// prepare nonces
		nonce1 := make([]byte, b.nonce)
		copy(nonce1, b.nonce)

		nonce2 := make([]byte, b.nonce)
		copy(nonce2, b.nonce)

		// buffer for box of current
		boxed := make([]byte, 0, len(current)+secretbox.Overhead)
		boxed = secretbox.Seal(boxed, current, increment(nonce2), b.key)

		// define and populate header
		hdrPlain := &bytes.Buffer{make([]byte, 18)}

		_, err := binary.Write(hdrPlain, bytes.BigEndian, len(buf))
		if err != nil {
			return 0, err
		}

		// slice mac from box
		mac := boxed[:16]

		copy(hdrPlain[2:], mac)

		hdrBox := make([]byte, 0, HeaderLength)
		hdrBox = secretbox.Seal(hdrBox, hdrPlain, nonce1, b.key)

		increment(increment(nonce1))
		increment(nonce2)

		_, err = b.w.Write(hdrBox)
		if err != nil {
			return nil, err
		}

		return b.w.Write(boxed[HeaderLength:])
	}
}
