package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
)

func TestServersJSONSectionIsOmittedWhenEmpty(t *testing.T) {
	b, err := json.Marshal(serversJSON([]providers.CertServer{{Names: []string{"a"}, File: "/f", Line: 1}}))
	require.NoError(t, err)
	assert.JSONEq(t, `[{"names":["a"],"listens":[],"file":"/f","line":1}]`, string(b))
	b, err = json.Marshal(serversJSON([]providers.CertServer{{Names: []string{"a"}, File: "/f", Line: 1, Section: "fe_https"}}))
	require.NoError(t, err)
	assert.JSONEq(t, `[{"names":["a"],"listens":[],"file":"/f","line":1,"section":"fe_https"}]`, string(b))
}
