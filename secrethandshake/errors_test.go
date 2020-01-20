package secrethandshake

import (
	"errors"
	"io"
	"testing"
)

func TestUnwrapErr(t *testing.T) {

	var procErr = ErrProcessing{
		where: "test",
		cause: io.EOF,
	}

	unwrapped := errors.Unwrap(procErr)
	if unwrapped != io.EOF {
		t.Error("not EOF, got:", unwrapped)
	}

	var encErr = ErrEncoding{
		what:  "test enc",
		cause: io.ErrUnexpectedEOF,
	}

	unwrapped = errors.Unwrap(encErr)
	if unwrapped != io.ErrUnexpectedEOF {
		t.Error("not EOF, got:", unwrapped)
	}
}
