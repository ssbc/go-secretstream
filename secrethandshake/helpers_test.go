package secrethandshake

import (
	"encoding/base64"
	"encoding/json"
	"os"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func mustLoadTestKeyPair(fname string) EdKeyPair {
	f, err := os.Open(fname)
	check(err)
	defer f.Close()

	var t struct {
		PublicKey, SecretKey string
	}
	check(json.NewDecoder(f).Decode(&t))

	pubClient, err := base64.StdEncoding.DecodeString(t.PublicKey)
	check(err)

	secSrv, err := base64.StdEncoding.DecodeString(t.SecretKey)
	check(err)

	var kp EdKeyPair
	copy(kp.Public[:], pubClient)
	copy(kp.Secret[:], secSrv)
	return kp
}
