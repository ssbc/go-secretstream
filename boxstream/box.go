// SPDX-License-Identifier: MIT

package boxstream

import (
	"bytes"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// HeaderLength defines the length of the header packet before the body
	HeaderLength = 2 + 16 + 16

	// MaxSegmentSize is the maximum body size for boxstream packets
	MaxSegmentSize = 4 * 1024
)

var goodbye [18]byte

// Boxer encrypts everything that is written to it
type Boxer struct {
	w      io.Writer
	secret *[32]byte
	nonce  *[24]byte
}

// writeMessage writes a boxstream packet to the underlying writer.
func (b *Boxer) writeMessage(msg []byte) error {
	if len(msg) > MaxSegmentSize {
		panic("message exceeds maximum segment size")
	}
	headerNonce := *b.nonce
	increment(b.nonce)
	bodyNonce := *b.nonce
	increment(b.nonce)

	// construct body box
	bodyBox := secretbox.Seal(nil, msg, &bodyNonce, b.secret)
	bodyMAC, body := bodyBox[:secretbox.Overhead], bodyBox[secretbox.Overhead:]

	// construct header box
	header := make([]byte, 2+secretbox.Overhead)
	binary.BigEndian.PutUint16(header[:2], uint16(len(msg)))
	copy(header[2:], bodyMAC)
	headerBox := secretbox.Seal(nil, header, &headerNonce, b.secret)

	// write header + body
	if _, err := b.w.Write(headerBox); err != nil {
		return err
	}
	_, err := b.w.Write(body)
	return err
}

// Write implements io.Writer.
func (b *Boxer) Write(p []byte) (int, error) {
	buf := bytes.NewBuffer(p)
	for buf.Len() > 0 {
		if err := b.writeMessage(buf.Next(MaxSegmentSize)); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Close implements io.Closer. It writes the 'goodbye' protocol message to the underlying writer.
func (b *Boxer) Close() error {
	_, err := b.w.Write(secretbox.Seal(nil, goodbye[:], b.nonce, b.secret))
	return err
}

// NewBoxer returns a Boxer wich encrypts everything that is written to the passed writer
func NewBoxer(w io.Writer, nonce *[24]byte, secret *[32]byte) io.WriteCloser {
	return &Boxer{
		w:      w,
		secret: secret,
		nonce:  nonce,
	}
}

func increment(b *[24]byte) *[24]byte {
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
