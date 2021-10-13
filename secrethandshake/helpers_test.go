// SPDX-FileCopyrightText: 2021 The Secretstream Authors
//
// SPDX-License-Identifier: MIT

package secrethandshake

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func checker(t *testing.T) func(err error) {
	return func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func mustLoadTestKeyPair(t *testing.T, fname string) EdKeyPair {
	check := checker(t)

	f, err := os.Open(fname)
	check(err)
	defer f.Close()

	var keyPair struct {
		PublicKey, SecretKey string
	}
	check(json.NewDecoder(f).Decode(&keyPair))

	var kp EdKeyPair
	kp.Public, err = base64.StdEncoding.DecodeString(keyPair.PublicKey)
	check(err)
	kp.Secret, err = base64.StdEncoding.DecodeString(keyPair.SecretKey)
	check(err)

	return kp
}
