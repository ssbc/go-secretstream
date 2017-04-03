package stateless

import (
	"encoding/hex"
	"strings"
)

// TODO: only expose in tests?
func (s *State) ToJsonState() *JsonState {

	return &JsonState{
		AppKey: hex.EncodeToString(s.appKey),
		Local: localKey{
			KxPK:      hex.EncodeToString(s.ephKeyPair.Public[:]),
			KxSK:      hex.EncodeToString(s.ephKeyPair.Secret[:]),
			PublicKey: hex.EncodeToString(s.local.Public[:]),
			SecretKey: hex.EncodeToString(s.local.Secret[:]),
			AppMac:    hex.EncodeToString(s.localAppMac),
		},
		Remote: remotePub{hex.EncodeToString(s.remotePublic[:])},
		Random: hex.EncodeToString(s.ephRandBuf.Bytes()),
	}
}

// json test vectors > go conversion boilerplate
type localKey struct {
	KxPK      string `mapstructure:"kx_pk"`
	KxSK      string `mapstructure:"kx_sk"`
	PublicKey string `mapstructure:"publicKey"`
	SecretKey string `mapstructure:"secretKey"`
	AppMac    string `mapstructure:"app_mac"`
}

type remotePub struct {
	PublicKey string `mapstructure:"publicKey"`
}

type JsonState struct {
	AppKey string    `mapstructure:"app_key"`
	Local  localKey  `mapstructure:"local"`
	Remote remotePub `mapstructure:"remote"`
	Seed   string    `mapstructure:"seed"`
	Random string    `mapstructure:"random"`
}

func JsonStateToOurState(s JsonState) (*State, error) {
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
	)
}
