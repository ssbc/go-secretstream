// SPDX-License-Identifier: MIT

package boxstream

import (
	"io"
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

	wErrc := make(chan error)
	checkW := mkCheckOnce(wErrc)
	cErrc := make(chan error)
	checkC := mkCheckOnce(cErrc)
	go func() {
		err := bw.WriteMessage([]byte{0, 1, 2, 3, 4, 5})
		checkW(err)

		err = bw.WriteGoodbye()
		checkC(err)
	}()

	rx, err := br.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := <-wErrc; ok {
		t.Fatal(e)
	}
	if len(rx) != 6 {
		t.Error("rx len wrong")
	}

	for i, x := range rx {
		if i != int(x) {
			t.Errorf("expected %v, got %v", i, x)
		}
	}

	rx, err = br.ReadMessage()
	if err != io.EOF {
		t.Fatal(err)
	} else if len(rx) != 0 {
		t.Errorf("more data?")
	}

	if e, ok := <-cErrc; ok {
		t.Fatal(e)
	}

}
