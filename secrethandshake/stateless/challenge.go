package stateless

func CreateChallenge(state *State) []byte {
	return append(state.localAppMac, state.ephKeyPair.Public[:]...)
}
