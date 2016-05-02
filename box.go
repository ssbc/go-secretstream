package boxstream

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/nacl/secretbox"
)

func init() {
	log.SetOutput(os.Stderr)
}

const (
	HeaderLength   = 2 + 16 + 16
	MaxSegmentSize = 4 * 1024
)

var (
	WrongKeyLength   = fmt.Errorf("wrong key length")
	WrongNonceLength = fmt.Errorf("wrong nonce length")
	final            [18]byte
)

type Boxer struct {
	input  *io.PipeReader
	output io.Writer
	secret *[32]byte
	nonce  *[24]byte
}

type Unboxer struct {
	input  io.Reader
	output *io.PipeWriter
	secret *[32]byte
	nonce  *[24]byte
}

func NewBoxer(w io.Writer, nonce *[24]byte, secret *[32]byte) io.WriteCloser {
	pr, pw := io.Pipe()
	b := &Boxer{
		input:  pr,
		output: w,
		secret: secret,
		nonce:  nonce,
	}
	go b.loop()
	return pw
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

		// zero header indicates termination
		if bytes.Equal(final[:], hdr) {
			u.output.Close()
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

func (b *Boxer) loop() {
	var running = true
	var eof = false
	var nonce1, nonce2 [24]byte

	sentLen := 0

	check := func(err error) {
		if err != nil {
			running = false
			log.Println("boxer loop: closing:", err)
			if err2 := b.input.CloseWithError(err); err2 != nil {
				log.Println("boxer loop: couldn't close:", err2)
			}
		}
	}

	// prepare nonces
	copy(nonce1[:], b.nonce[:])
	copy(nonce2[:], b.nonce[:])

	for running {

		msg := make([]byte, MaxSegmentSize)
		n, err := io.ReadAtLeast(b.input, msg, 1)
		if err == io.EOF {
			eof = true
			running = false
		} else {
			check(err)
		}
		msg = msg[:n]

		log.Printf("write: loop top. got: %d sent: %d", n, sentLen)

		// buffer for box of current
		boxed := secretbox.Seal(nil, msg, increment(&nonce2), b.secret)
		// define and populate header
		var hdrPlain = bytes.NewBuffer(nil)
		err = binary.Write(hdrPlain, binary.BigEndian, uint16(len(msg)))
		check(err)
		log.Printf("writerloop: boxed: %x (%d)", boxed, len(boxed))

		// slice mac from box
		_, err = hdrPlain.Write(boxed[:16]) // ???
		check(err)

		log.Printf("writerloop: header nonce is  %x\n", &nonce1)
		log.Printf("writerloop: header secret is %x\n", b.secret)
		if eof {
			hdrPlain = bytes.NewBuffer(final[:])
		}
		hdrBox := secretbox.Seal(nil, hdrPlain.Bytes(), &nonce1, b.secret)
		log.Printf("writerloop: box is %x\n", hdrBox)
		log.Printf("writerloop: box len %v\n", len(hdrBox))

		increment(increment(&nonce1))
		increment(&nonce2)

		n, err = b.output.Write(hdrBox)
		check(err)
		log.Println("writer: wrote header; n is", n)
		sentLen += n

		n2, err := io.Copy(b.output, bytes.NewBuffer(boxed[secretbox.Overhead:]))
		log.Println("writer: wrote body; n is", n2)
		check(err)
		sentLen += int(n2)

	}
}
