// SPDX-License-Identifier: MIT

package secrethandshake

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"

	"github.com/pkg/errors"
)

func LoadSSBKeyPair(fname string) (*EdKeyPair, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, errors.Wrapf(err, "secrethandshake: could not open key file")
	}
	defer f.Close()

	var sbotKey struct {
		Curve   string `json:"curve"`
		ID      string `json:"id"`
		Private string `json:"private"`
		Public  string `json:"public"`
	}

	if err := json.NewDecoder(f).Decode(&sbotKey); err != nil {
		return nil, errors.Wrapf(err, "secrethandshake: json decoding of %q failed.", fname)
	}

	public, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(sbotKey.Public, ".ed25519"))
	if err != nil {
		return nil, errors.Wrapf(err, "secrethandshake: base64 decode of public part failed.")
	}

	private, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(sbotKey.Private, ".ed25519"))
	if err != nil {
		return nil, errors.Wrapf(err, "secrethandshake: base64 decode of private part failed.")
	}

	var kp EdKeyPair
	copy(kp.Public[:], public)
	copy(kp.Secret[:], private)
	return &kp, nil
}
