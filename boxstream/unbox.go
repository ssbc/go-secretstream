// SPDX-License-Identifier: MIT

package boxstream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// Unboxer decrypts everything that is read from it
type Unboxer struct {
	input  io.Reader
	output *io.PipeWriter
	secret *[32]byte
	nonce  *[24]byte
}

// NewUnboxer wraps the passed input Reader into an Unboxer
func NewUnboxer(input io.Reader, nonce *[24]byte, secret *[32]byte) io.ReadCloser {
	pr, pw := io.Pipe()
	unboxer := &Unboxer{
		input:  input,
		output: pw,
		secret: secret,
		nonce:  nonce,
	}
	go unboxer.readerloop()
	return pr
}

func (u *Unboxer) readerloop() {
	hdrBox := make([]byte, HeaderLength)
	hdr := make([]byte, 0, HeaderLength-secretbox.Overhead)
	var ok bool
	for {
		hdr = hdr[:0]
		_, err := io.ReadFull(u.input, hdrBox)
		if err != nil {
			u.output.CloseWithError(err)
			return
		}

		hdr, ok = secretbox.Open(hdr, hdrBox, u.nonce, u.secret)
		if !ok {
			u.output.CloseWithError(errors.New("boxstream: error opening header box"))
			return
		}

		// zero header indicates termination
		if bytes.Equal(final[:], hdr) {
			u.output.Close()
			return
		}

		n := binary.BigEndian.Uint16(hdr[:2])

		buf := make([]byte, n+secretbox.Overhead)

		tag := hdr[2:] // len(tag) == seceretbox.Overhead

		copy(buf[:secretbox.Overhead], tag)

		_, err = io.ReadFull(u.input, buf[len(tag):])
		if err != nil {
			u.output.CloseWithError(err)
			return
		}

		out := make([]byte, 0, n)
		out, ok = secretbox.Open(out, buf, increment(u.nonce), u.secret)
		if !ok {
			u.output.CloseWithError(errors.New("boxstream: error opening body box"))
			return
		}

		_, err = io.Copy(u.output, bytes.NewReader(out))
		if err != nil {
			u.output.CloseWithError(err)
			return
		}
		increment(u.nonce)
	}
}
