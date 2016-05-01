package boxstream

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/nacl/secretbox"
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
	output io.Writer
	secret *[32]byte
	nonce  *[24]byte
}

type Unboxer struct {
	output *io.PipeWriter
	input  io.Reader
	secret *[32]byte
	nonce  *[24]byte
}

func NewBoxer(w io.Writer, nonce *[24]byte, secret *[32]byte) io.Writer {
	return &Boxer{
		output: w,
		secret: secret,
		nonce:  nonce,
	}
}

func NewUnboxer(input io.Reader, nonce *[24]byte, secret *[32]byte) io.Reader {
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

func (u *Unboxer) readerloop() {
	hdrBox := make([]byte, HeaderLength)
	hdr := make([]byte, 0, HeaderLength-secretbox.Overhead)
	var ok bool
	for {
		hdr = hdr[:0]
		_, err := io.ReadFull(u.input, hdrBox)
		log.Println("readerloop: read header")
		if err != nil {
			u.output.CloseWithError(err)
			return
		}

		log.Printf("renderloop: header nonce is  %x\n", u.nonce)
		log.Printf("readerloop: header secret is %x\n", u.secret)
		log.Printf("readerloop: box is %x\n", hdrBox)
		log.Printf("readerloop: box len %v\n", len(hdrBox))
		hdr, ok = secretbox.Open(hdr, hdrBox, u.nonce, u.secret)
		if !ok {
			u.output.CloseWithError(fmt.Errorf("error opening header box"))
			return
		}

		log.Println("readerloop: opened header box. len:", len(hdr))
		log.Printf("readerloop: header: %x\n", hdr)
		n := binary.BigEndian.Uint16(hdr[:2])

		buf := make([]byte, n+secretbox.Overhead)

		tag := hdr[2:] // len(tag) == seceretbox.Overhead

		log.Println("readerloop:", "n:", n, "tag len:", len(tag), "buf len", len(buf))

		copy(buf[:secretbox.Overhead], tag)

		_, err = io.ReadFull(u.input, buf[len(tag):])
		if err != nil {
			u.output.CloseWithError(err)
			return
		}

		log.Println("readerloop: read body")

		out := make([]byte, 0, n)
		out, ok = secretbox.Open(out, buf, increment(u.nonce), u.secret)
		if !ok {
			u.output.CloseWithError(fmt.Errorf("error opening body box"))
			return
		}
		log.Println("readerloop: opened body")

		_, err = io.Copy(u.output, bytes.NewBuffer(out))
		if err != nil {
			u.output.CloseWithError(err)
			return
		}
		increment(u.nonce)
		log.Println("readerloop: pkg decoded and fed to consumer")
	}
}

func (b *Boxer) Write(buf []byte) (int, error) {
	var current []byte
	var nonce1, nonce2 [24]byte

	log.Println("write: data length:", len(buf))

	sentLen := 0

	// segment large writes
	for len(buf) >= 0 {
		log.Println("write: loop top. sent:", sentLen)

		// fetch current segment
		if len(buf) < MaxSegmentSize {
			current = buf
		} else {
			current = buf[:MaxSegmentSize]
			buf = buf[MaxSegmentSize:]
		}

		// prepare nonces
		copy(nonce1[:], b.nonce[:])
		copy(nonce2[:], b.nonce[:])

		// buffer for box of current
		boxed := make([]byte, 0, len(current)+secretbox.Overhead)
		boxed = secretbox.Seal(boxed, current, increment(&nonce2), b.secret)

		// define and populate header
		hdrPlain := bytes.NewBuffer(make([]byte, 0, 18))

		err := binary.Write(hdrPlain, binary.BigEndian, uint16(len(buf)))
		if err != nil {
			return 0, err
		}

		// slice mac from box
		mac := boxed[:16]

		_, err = io.Copy(hdrPlain, bytes.NewBuffer(mac))
		if err != nil {
			return 0, err
		}

		log.Printf("writerloop: header nonce is  %x\n", &nonce1)
		log.Printf("writerloop: header secret is %x\n", b.secret)
		hdrBox := make([]byte, 0, HeaderLength)
		hdrBox = secretbox.Seal(hdrBox, hdrPlain.Bytes(), &nonce1, b.secret)
		log.Printf("writerloop: box is %x\n", hdrBox)
		log.Printf("writerloop: box len %v\n", len(hdrBox))

		increment(increment(&nonce1))
		increment(&nonce2)

		_, err = b.output.Write(hdrBox)
		if err != nil {
			return 0, err
		}

		_, err = io.Copy(b.output, bytes.NewBuffer(boxed[secretbox.Overhead:]))
		if err != nil {
			return 0, err
		}

		sentLen += len(current)
	}

	return sentLen, nil
}
