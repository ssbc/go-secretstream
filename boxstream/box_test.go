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
	"io"
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
}
