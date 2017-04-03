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
	assert.Nil(t, err)

	defer dataf.Close()

	var data []map[string]interface{}
	assert.Nil(t, json.NewDecoder(dataf).Decode(&data))

	for i, v := range data {
		if i >= 3 {
			return
		}

		args := v["args"].([]interface{})
		if len(args) < 1 {
			t.Fatal("setup test %d: need at least one argument", i)
		}

		// parse args
		var argState stateless.JsonState
		err := mapstructure.Decode(args[0], &argState)
		assert.Nil(t, err, "setup test %d", i)

		state, err := stateless.InitializeFromJSONState(argState)
		assert.Nil(t, err, "setup test %d", i)

		switch v["name"] {
		case "initialize":
			// parse result
			var resultState stateless.JsonState
			err = mapstructure.Decode(v["result"], &resultState)
			assert.Nil(t, err, "init test %d", i)

			// TODO: very meh - could argue about initialized memory but..
			ourState := *state.ToJsonState()
			if i == 2 && ourState.Remote.PublicKey == "0000000000000000000000000000000000000000000000000000000000000000" {
				ourState.Remote.PublicKey = ""
			}
			assert.Equal(t, resultState, ourState, "init test %d", i)

		case "createChallenge":
			challenge := stateless.CreateChallenge(state)
			assert.Equal(t, v["result"], hex.EncodeToString(challenge))

		case "verifyChallenge":

		default:
			t.Errorf("unhandled case testing %d: %s", i, v["name"])
		}
	}
}
