package boxstream

import (
	"io"
	"testing"
)

func TestBox(t *testing.T) {
	pr, pw := io.Pipe()

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

	go func() {
		_, err := bw.Write([]byte{0, 1, 2, 3, 4, 5})
		if err != nil {
			panic(err)
		}
	}()

	buf := make([]byte, 10)

	n, err := br.Read(buf[:6])
	if err != nil {
		panic(err)
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
}
