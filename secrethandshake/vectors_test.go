package secrethandshake

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cryptix/secretstream/secrethandshake/stateless"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
)

func TestVectors(t *testing.T) {
	dataf, err := os.Open("test-vectors/data.json")
	if os.IsNotExist(err) {
		t.Log("test-vectors data missing.")
		t.Log("please clone the test data using 'git submodule update --init' or similar.")
	}
	assert.Nil(t, err)
	defer dataf.Close()

	var data []map[string]interface{}
	assert.Nil(t, json.NewDecoder(dataf).Decode(&data))

	for i, v := range data {
		args := v["args"].([]interface{})
		if len(args) < 1 {
			t.Fatalf("setup test %d: need at least one argument", i)
		}

		if v["name"] == "toKeys" {
			t.Log("skipping toKeys")
			continue
		}

		// parse args
		var argState stateless.JsonState
		err := mapstructure.Decode(args[0], &argState)
		assert.Nil(t, err, "setup test %d", i)

		state, err := stateless.InitializeFromJSONState(argState)
		assert.Nil(t, err, "setup test %d", i)

		r, ok := v["result"]
		assert.True(t, ok)
		var negTest = r == nil

		switch v["name"] {
		case "initialize":
			var resultState stateless.JsonState
			err = mapstructure.Decode(r, &resultState)
			assert.Nil(t, err, "init test %d", i)
			assert.Equal(t, resultState, *state.ToJsonState(), "init test %d", i)

		case "createChallenge":
			challenge := stateless.CreateChallenge(state)
			assert.Equal(t, r, hex.EncodeToString(challenge))

		case "verifyChallenge":
			challenge, err := hex.DecodeString(args[1].(string))
			assert.Nil(t, err, "verifyChallenge test %d", i)
			nextState := stateless.VerifyChallenge(state, challenge)
			if negTest {
				assert.Nil(t, nextState)
			} else {
				assert.NotNil(t, nextState, "verifyChallenge test %d", i)
				var resultState stateless.JsonState
				err = mapstructure.Decode(r, &resultState)
				assert.Nil(t, err, "verifyChallenge test %d", i)
				assert.Equal(t, resultState, *nextState.ToJsonState(), "verifyChallenge test %d", i)
			}

		case "clientVerifyChallenge":
			challenge, err := hex.DecodeString(args[1].(string))
			assert.Nil(t, err, "clientVerifyChallenge test %d", i)
			nextState := stateless.ClientVerifyChallenge(state, challenge)
			if negTest {
				assert.Nil(t, nextState)
			} else {
				var resultState stateless.JsonState
				err = mapstructure.Decode(r, &resultState)
				assert.Nil(t, err, "clientVerifyChallenge test %d", i)
				assert.Equal(t, resultState, *nextState.ToJsonState(), "clientVerifyChallenge test %d", i)
			}

		case "clientCreateAuth":
			auth := stateless.ClientCreateAuth(state)
			assert.Equal(t, r, hex.EncodeToString(auth), "clientCreateAuth test %d", i)

		case "serverVerifyAuth":
			challenge, err := hex.DecodeString(args[1].(string))
			assert.Nil(t, err, "serverVerifyAuth test %d", i)
			nextState := stateless.ServerVerifyAuth(state, challenge)
			if negTest {
				assert.Nil(t, nextState)
			} else {
				assert.NotNil(t, nextState, "serverVerifyAuth test %d", i)
				var expected, derived stateless.JsonState
				err = mapstructure.Decode(r, &expected)
				assert.Nil(t, err, "serverVerifyAuth test %d", i)
				derived = *nextState.ToJsonState()
				assert.Equal(t, expected, derived, "serverVerifyAuth test %d", i)
			}

		case "serverCreateAccept":
			accept := stateless.ServerCreateAccept(state)
			assert.Equal(t, r, hex.EncodeToString(accept), "serverCreateAccept test %d", i)

		case "clientVerifyAccept":
			acc, err := hex.DecodeString(args[1].(string))
			assert.Nil(t, err, "clientVerifyAccept test %d", i)
			nextState := stateless.ClientVerifyAccept(state, acc)
			assert.NotNil(t, nextState, "clientVerifyAccept test %d", i)
			var resultState stateless.JsonState
			err = mapstructure.Decode(r, &resultState)
			assert.Nil(t, err, "clientVerifyAccept test %d", i)
			derived := *nextState.ToJsonState()
			assert.Equal(t, resultState, derived, "clientVerifyAccept test %d", i)

		default:
			t.Errorf("unhandled case testing %d: %s", i, v["name"])
		}
	}
}
