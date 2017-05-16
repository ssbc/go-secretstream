package stateless

import (
	"encoding/hex"
	"strings"
)

func stripIfZero(s string) string {
	if s == "0000000000000000000000000000000000000000000000000000000000000000" {
		s = ""
	}
	return s
}

// TODO: only expose in tests?
func (s *State) ToJsonState() *JsonState {

	rpubStr := hex.EncodeToString(s.remotePublic[:])
	rephPubStr := hex.EncodeToString(s.ephKeyRemotePub[:])
	secStr := hex.EncodeToString(s.secret[:])
	sec2Str := hex.EncodeToString(s.secret2[:])
	abobStr := hex.EncodeToString(s.aBob[:])

	// zero value means long sequence of "0000..."
	for _, s := range []*string{
		&rpubStr,
		&rephPubStr,
		&secStr,
		&sec2Str,
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
			Hello:     hex.EncodeToString(s.hello),
		},
		Remote: remoteKey{
			PublicKey: rpubStr,
			EphPubKey: rephPubStr,
			AppMac:    hex.EncodeToString(s.remoteAppMac),
		},
		Random:  hex.EncodeToString(s.ephRandBuf.Bytes()),
		Secret:  secStr,
		Secret2: sec2Str,
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
}

type JsonState struct {
	AppKey  string    `mapstructure:"app_key"`
	Local   localKey  `mapstructure:"local"`
	Remote  remoteKey `mapstructure:"remote"`
	Seed    string    `mapstructure:"seed"`
	Random  string    `mapstructure:"random"`
	Secret  string    `mapstructure:"secret"`
	Secret2 string    `mapstructure:"secret2"`
	ABob    string    `mapstructure:"a_bob"`
}

func InitializeFromJSONState(s JsonState) (*State, error) {
	var localKeyPair Option
	if s.Seed != "" {
		localKeyPair = LocalKeyFromSeed(strings.NewReader(s.Seed))
	} else {
		localKeyPair = LocalKeyFromHex(s.Local.PublicKey, s.Local.SecretKey)
	}
	return Initialize(
		SetAppKey(s.AppKey),
		localKeyPair,
		EphemeralRandFromHex(s.Random),
		RemotePubFromHex(s.Remote.PublicKey),
		func(state *State) error {
			if s.Local.Hello != "" {
				var err error
				state.hello, err = hex.DecodeString(s.Local.Hello)
				if err != nil {
					return err
				}
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
	)
}
