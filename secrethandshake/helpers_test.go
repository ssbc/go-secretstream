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

	var kp EdKeyPair
	kp.Public, err = base64.StdEncoding.DecodeString(t.PublicKey)
	check(err)
	kp.Secret, err = base64.StdEncoding.DecodeString(t.SecretKey)
	check(err)

	return kp
}
