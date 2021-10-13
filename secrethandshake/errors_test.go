// SPDX-FileCopyrightText: 2021 The Secretstream Authors
//
// SPDX-License-Identifier: MIT

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
		t.Error("does not unwrap to EOF, got:", unwrapped)
	}

	if !errors.Is(procErr, io.EOF) {
		t.Error("errors.Is(err,eof) not true")
	}

	var encErr = ErrEncoding{
		what:  "test enc",
		cause: io.ErrUnexpectedEOF,
	}

	unwrapped = errors.Unwrap(encErr)
	if unwrapped != io.ErrUnexpectedEOF {
		t.Error("not unexpected EOF, got:", unwrapped)
	}

	if !errors.Is(encErr, io.ErrUnexpectedEOF) {
		t.Error("errors.Is(err,unexpected EOF) not true")
	}

}
