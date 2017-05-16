package stateless

import "golang.org/x/crypto/nacl/box"

func ClientCreateAuth(state *State) []byte {
	var n [24]byte
	return box.SealAfterPrecomputation(nil, state.hello, &n, &state.secret2)
}
