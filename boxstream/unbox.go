/*
This file is part of secretstream.

secretstream is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

secretstream is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with secretstream.  If not, see <http://www.gnu.org/licenses/>.
*/

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
	r      io.Reader
	msg    []byte
	secret *[32]byte
	nonce  *[24]byte
}

// readNextBox reads the next message from the underlying stream.
func (u *Unboxer) readNextBox() error {
	headerNonce := *u.nonce
	increment(u.nonce)
	bodyNonce := *u.nonce
	increment(u.nonce)

	// read and unbox header
	headerBox := make([]byte, 2+secretbox.Overhead+secretbox.Overhead)
	if _, err := io.ReadFull(u.r, headerBox); err != nil {
		return err
	}
	header, ok := secretbox.Open(nil, headerBox, &headerNonce, u.secret)
	if !ok {
		return errors.New("invalid header box")
	}

	// zero header indicates termination
	if bytes.Equal(header, goodbye[:]) {
		return io.EOF
	}

	// read and unbox body
	bodyLen := binary.BigEndian.Uint16(header[:2])
	bodyBox := make([]byte, int(bodyLen)+secretbox.Overhead)
	if _, err := io.ReadFull(u.r, bodyBox[secretbox.Overhead:]); err != nil {
		return err
	}
	// prepend with MAC from header
	copy(bodyBox, header[2:])
	u.msg, ok = secretbox.Open(u.msg[:0], bodyBox, &bodyNonce, u.secret)
	if !ok {
		return errors.New("invalid body box")
	}
	return nil
}

// Read implements io.Reader.
func (u *Unboxer) Read(p []byte) (int, error) {
	if len(u.msg) == 0 {
		if err := u.readNextBox(); err != nil {
			return 0, err
		}
	}
	n := copy(p, u.msg)
	u.msg = u.msg[n:]
	return n, nil
}

// NewUnboxer wraps the passed Reader into an Unboxer.
func NewUnboxer(r io.Reader, nonce *[24]byte, secret *[32]byte) io.Reader {
	return &Unboxer{
		r:      r,
		secret: secret,
		nonce:  nonce,
	}
}
