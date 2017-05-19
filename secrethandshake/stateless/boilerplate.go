/*
This file is part of secretstream.

secretstream is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

secretstream is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with secretstream.  If not, see <http://www.gnu.org/licenses/>.
*/

package stateless

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
)

func stripIfZero(s string) string {
	if s == "0000000000000000000000000000000000000000000000000000000000000000" {
		s = ""
	}
	return s
}

// TODO: only expose in tests?
func (s *State) ToJsonState() *JsonState {
	if s == nil {
		panic("called ToJsonState on a nil state...")
	}

	rpubStr := hex.EncodeToString(s.remotePublic[:])
	rephPubStr := hex.EncodeToString(s.ephKeyRemotePub[:])
	secStr := hex.EncodeToString(s.secret[:])
	shStr := hex.EncodeToString(s.secHash[:])
	sec2Str := hex.EncodeToString(s.secret2[:])
	sec3Str := hex.EncodeToString(s.secret3[:])
	abobStr := hex.EncodeToString(s.aBob[:])

	// zero value means long sequence of "0000..."
	for _, s := range []*string{
		&rpubStr,
		&rephPubStr,
		&shStr,
		&secStr,
		&sec2Str,
		&sec3Str,
		&abobStr,
	} {
		*s = stripIfZero(*s)
	}

	return &JsonState{
		AppKey: hex.EncodeToString(s.appKey),
		Local: localKey{
			KxPK:      hex.EncodeToString(s.ephKeyPair.Public[:]),
			KxSK:      hex.EncodeToString(s.ephKeyPair.Secret[:]),
			PublicKey: hex.EncodeToString(s.local.Public[:]),
			SecretKey: hex.EncodeToString(s.local.Secret[:]),
			AppMac:    hex.EncodeToString(s.localAppMac),
			Hello:     hex.EncodeToString(s.localHello),
		},
		Remote: remoteKey{
			PublicKey: rpubStr,
			EphPubKey: rephPubStr,
			AppMac:    hex.EncodeToString(s.remoteAppMac),
			Hello:     hex.EncodeToString(s.remoteHello),
		},
		Random:  hex.EncodeToString(s.ephRandBuf.Bytes()),
		Seed:    hex.EncodeToString(s.seedBuf.Bytes()),
		Secret:  secStr,
		SecHash: shStr,
		Secret2: sec2Str,
		Secret3: sec3Str,
		ABob:    abobStr,
	}
}

// json test vectors > go conversion boilerplate
type localKey struct {
	KxPK      string `mapstructure:"kx_pk"`
	KxSK      string `mapstructure:"kx_sk"`
	PublicKey string `mapstructure:"publicKey"`
	SecretKey string `mapstructure:"secretKey"`
	AppMac    string `mapstructure:"app_mac"`
	Hello     string `mapstructure:"hello"`
}

type remoteKey struct {
	PublicKey string `mapstructure:"publicKey"`
	EphPubKey string `mapstructure:"kx_pk"`
	AppMac    string `mapstructure:"app_mac"`
	Hello     string `mapstructure:"hello"`
}

type JsonState struct {
	AppKey  string    `mapstructure:"app_key"`
	Local   localKey  `mapstructure:"local"`
	Remote  remoteKey `mapstructure:"remote"`
	Seed    string    `mapstructure:"seed"`
	Random  string    `mapstructure:"random"`
	SecHash string    `mapstructure:"shash"`
	Secret  string    `mapstructure:"secret"`
	Secret2 string    `mapstructure:"secret2"`
	Secret3 string    `mapstructure:"secret3"`
	ABob    string    `mapstructure:"a_bob"`
}

func InitializeFromJSONState(s JsonState) (*State, error) {
	var localKeyPair Option
	if s.Seed != "" {
		seed, err := hex.DecodeString(s.Seed)
		if err != nil {
			return nil, err
		}
		localKeyPair = LocalKeyFromSeed(bytes.NewReader(seed))
	} else {
		localKeyPair = LocalKeyFromHex(s.Local.PublicKey, s.Local.SecretKey)
	}
	return Initialize(
		SetAppKeyFromHex(s.AppKey),
		localKeyPair,
		EphemeralRandFromHex(s.Random),
		RemotePubFromHex(s.Remote.PublicKey),
		func(state *State) error {
			if s.Local.AppMac != "" {
				var err error
				state.localAppMac, err = hex.DecodeString(s.Local.AppMac)
				if err != nil {
					return err
				}

			}
			return nil
		},
		func(state *State) error {
			if s.Remote.AppMac != "" {
				var err error
				state.remoteAppMac, err = hex.DecodeString(s.Remote.AppMac)
				if err != nil {
					return err
				}
			}
			return nil
		},
		func(state *State) error {
			if s.Local.Hello != "" {
				var err error
				state.localHello, err = hex.DecodeString(s.Local.Hello)
				if err != nil {
					return err
				}
			}
			return nil
		},
		func(state *State) error {
			if s.Remote.Hello != "" {
				var err error
				state.remoteHello, err = hex.DecodeString(s.Remote.Hello)
				if err != nil {
					return err
				}
			}
			return nil
		},
		func(state *State) error {
			if s.ABob != "" {
				data, err := hex.DecodeString(s.ABob)
				if err != nil {
					return err
				}
				copy(state.aBob[:], data)
			}
			return nil
		},
		func(state *State) error {
			if s.Secret != "" {
				s, err := hex.DecodeString(s.Secret)
				if err != nil {
					return err
				}
				copy(state.secret[:], s)
			}
			return nil
		},
		func(state *State) error {
			if s.Secret2 != "" {
				s2, err := hex.DecodeString(s.Secret2)
				if err != nil {
					return err
				}
				copy(state.secret2[:], s2)
			}
			return nil
		},
		func(state *State) error {
			if s.Secret3 != "" {
				s2, err := hex.DecodeString(s.Secret3)
				if err != nil {
					return err
				}
				copy(state.secret3[:], s2)
			}
			return nil
		},

		func(state *State) error {
			if s.Remote.EphPubKey != "" {
				r, err := hex.DecodeString(s.Remote.EphPubKey)
				if err != nil {
					return err
				}
				copy(state.ephKeyRemotePub[:], r)
			}
			return nil
		},
		func(state *State) error {
			if s.SecHash != "" {
				var err error
				state.secHash, err = hex.DecodeString(s.SecHash)
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
}

// WIP: DRY for the above
func fill(field, value string) Option {
	return func(s *State) error {
		if value != "" {
			b, err := hex.DecodeString(value)
			if err != nil {
				return err
			}
			t, ok := reflect.TypeOf(*s).FieldByName(field)
			if !ok {
				return fmt.Errorf("field not found")
			}

			fmt.Println("Len:", t.Type.Len())
			const l = 32 // t.Type.Len()

			v := reflect.ValueOf(*s).FieldByName(field).Interface().([l]uint8)
			copy(v[:], b)
		}
		return nil
	}
}
