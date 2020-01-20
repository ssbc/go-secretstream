package secrethandshake

import (
	"fmt"
	"strconv"
)

type ErrProtocol struct{ code int }

func (eh ErrProtocol) Error() string {
	switch eh.code {
	case 0:
		return "secrethandshake: Wrong protocol version?"
	case 1:
		return "secrethandshake: other side not authenticated"
	default:

		return "shs: unhandled error " + strconv.Itoa(eh.code)
	}
}

// ErrProcessing is returned if I/O fails during the handshake
// TODO: supply Unwrap() for cause?
type ErrProcessing struct {
	where string
	cause error
}

func (ep ErrProcessing) Error() string {
	errStr := "secrethandshake: failed during data transfer of " + ep.where
	errStr += " : " + ep.cause.Error()
	return errStr
}

var ErrInvalidKeyPair = fmt.Errorf("secrethandshake/NewKeyPair: invalid public key")

type ErrKeySize struct {
	tipe string
	n    int
}

func (eks ErrKeySize) Error() string {
	return fmt.Sprintf("secrethandshake/NewKeyPair: invalid size (%d) for %s key", eks.n, eks.tipe)
}

type ErrEncoding struct {
	what  string
	cause error
}

func (eenc ErrEncoding) Error() string {
	errStr := "secrethandshake: failed during encoding task of " + eenc.what
	errStr += " : " + eenc.cause.Error()
	return errStr
}
