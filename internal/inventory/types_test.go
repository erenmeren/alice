package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWebServerTypes(t *testing.T) {
	assert.True(t, IsWebServer("nginx"))
	assert.True(t, IsWebServer("apache"))
	assert.True(t, IsServer("apache"))
	for _, typ := range []string{"linux", "azure_key_vault", "", "NGINX"} {
		assert.False(t, IsWebServer(typ), typ)
	}
	assert.True(t, IsServer("linux"))
	assert.True(t, IsServer("nginx"))
	assert.False(t, IsServer("azure_key_vault"))
	assert.Equal(t, []string{"nginx", "apache"}, WebServerTypes())
	got := WebServerTypes()
	got[0] = "changed"
	assert.Equal(t, []string{"nginx", "apache"}, WebServerTypes(), "the list is a copy")
}
