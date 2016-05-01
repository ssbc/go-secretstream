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
	w      io.Writer
	secret *[32]byte
	nonce  *[24]byte
}

type Unboxer struct {
	//pipe
	io.Reader
	pw *io.PipeWriter

	r      io.Reader
	secret *[32]byte
	nonce  *[24]byte
}

func NewBoxer(w io.Writer, nonce *[24]byte, secret *[32]byte) io.Writer {
	return &Boxer{w: w, secret: secret, nonce: nonce}
}

func NewUnboxer(r io.Reader, nonce *[24]byte, secret *[32]byte) io.Reader {
	unboxer := &Unboxer{r: r, secret: secret, nonce: nonce}
	unboxer.Reader, unboxer.pw = io.Pipe()

	go unboxer.readerloop()

	return unboxer
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
		_, err := io.ReadFull(u.r, hdrBox)
		log.Println("readerloop: read header")
		if err != nil {
			u.pw.CloseWithError(err)
			return
		}

		increment(u.nonce)
		log.Printf("renderloop: header nonce is  %x\n", u.nonce)
		log.Printf("readerloop: header secret is %x\n", u.secret)
		log.Printf("readerloop: box is %x\n", hdrBox)
		hdr, ok = secretbox.Open(hdr, hdrBox, u.nonce, u.secret)
		if !ok {
			u.pw.CloseWithError(fmt.Errorf("error opening header box"))
			return
		}

		log.Println("readerloop: opened header box")
		n := binary.LittleEndian.Uint16(hdr[:2])

		buf := make([]byte, n)

		tag := hdr[2:]
		copy(buf[:16], tag)

		_, err = io.ReadFull(u.r, buf[len(tag):])
		if err != nil {
			u.pw.CloseWithError(err)
			return
		}

		log.Println("readerloop: read body")

		out := make([]byte, 0, n)
		out, ok = secretbox.Open(out, buf, increment(u.nonce), u.secret)
		if !ok {
			u.pw.CloseWithError(fmt.Errorf("error opening body box"))
			return
		}
		log.Println("readerloop: opened body")

		_, err = io.Copy(u.pw, bytes.NewBuffer(out))
		if err != nil {
			u.pw.CloseWithError(err)
			return
		}
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
		increment(&nonce2)
		log.Printf("writerloop: header nonce is  %x\n", &nonce2)
		log.Printf("writerloop: header secret is %x\n", b.secret)
		boxed = secretbox.Seal(boxed, current, &nonce2, b.secret)
		log.Printf("writerloop: box is %x\n", boxed)

		// define and populate header
		hdrPlain := bytes.NewBuffer(make([]byte, 18))

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

		hdrBox := make([]byte, 0, HeaderLength)
		hdrBox = secretbox.Seal(hdrBox, hdrPlain.Bytes(), &nonce1, b.secret)

		increment(increment(&nonce1))
		increment(&nonce2)

		_, err = b.w.Write(hdrBox)
		if err != nil {
			return 0, err
		}

		_, err = io.Copy(b.w, bytes.NewBuffer(boxed[HeaderLength:]))
		if err != nil {
			return 0, err
		}

		sentLen += len(current)
	}

	return sentLen, nil
}
