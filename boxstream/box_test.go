// SPDX-License-Identifier: MIT

package boxstream

import (
	"net"
	"testing"
)

func mkCheckOnce(errc chan<- error) func(error) {
	return func(err error) {
		if err != nil {
			errc <- err
		} else {
			close(errc)
		}
	}
}

func TestBox(t *testing.T) {
	pr, pw := net.Pipe()

	var secret [32]byte
	var boxnonce [24]byte
	var unboxnonce [24]byte

	for i := range secret {
		secret[i] = byte(3 * i)
	}
	for i := range boxnonce {
		boxnonce[i] = byte(5 * i)
	}

	copy(unboxnonce[:], boxnonce[:])

	bw := NewBoxer(pw, &boxnonce, &secret)
	br := NewUnboxer(pr, &unboxnonce, &secret)

	errc := make(chan error)
	check := mkCheckOnce(errc)
	go func() {
		_, err := bw.Write([]byte{0, 1, 2, 3, 4, 5})
		check(err)
	}()

	buf := make([]byte, 10)

	n, err := br.Read(buf[:6])
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := <-errc; ok {
		t.Fatal(e)
	}

	rx := buf[:n]

	if len(rx) != 6 {
		t.Error("rx len wrong")
	}

	for i, x := range rx {
		if i != int(x) {
			t.Errorf("expected %v, got %v", i, x)
		}
	}

	err = br.Close()
	if err != nil {
		t.Fatal(err)
	}

	err = bw.Close()
	if err != nil {
		t.Fatal(err)
	}

}
