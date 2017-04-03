package stateless

import "golang.org/x/crypto/nacl/box"

func ClientCreateAuth(state *State) []byte {
	out := make([]byte, 0, len(state.hello)-box.Overhead)
	var n [24]byte
	box.SealAfterPrecomputation(out, state.hello, &n, &state.secret2)
	return out
}
