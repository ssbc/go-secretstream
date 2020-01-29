package secrethandshake

import (
	"testing"
)

func TestUnsafeBoolCase(t *testing.T) {
	if err := testMemoryLayoutAssumption(); err != nil {
		t.Fatal(err)
	}
}
