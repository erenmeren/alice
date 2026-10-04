package inventory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/providers"
)

func TestKVSmallHelpers(t *testing.T) {
	assert.Equal(t, "inventory: the vault is deleted", kvDropped("deleted").Error())
	a, b := time.Unix(1, 0), time.Unix(2, 0)
	assert.Equal(t, &a, firstTime(&a, &b))
	assert.Equal(t, &b, firstTime(nil, &b))
	assert.Nil(t, firstTime(nil, nil))
	assert.Equal(t, -1, compareStrings("a", "b"))
	assert.Equal(t, 1, compareStrings("b", "a"))
	assert.Equal(t, 0, compareStrings("a", "a"))
	assert.True(t, validKVText("öğe", 3))
	assert.False(t, validKVText("öğe", 2))
	assert.False(t, validKVText("a\x00", 5))
	assert.False(t, validKVText("a\xff", 5))
}

// The class table is shared by a failed poll and a failed list; precedence is the order of the constants.
func TestKVClassTable(t *testing.T) {
	order := []string{"internal.unexpected", "azure.throttled", "azure.forbidden", "azure.unreachable", "azure.auth_failed"}
	for i := 1; i < len(order); i++ {
		assert.Greater(t, int(kvClassOf(order[i])), int(kvClassOf(order[i-1])), order[i])
	}
	assert.Equal(t, kvClassOf("azure.firewall"), kvClassOf("azure.forbidden"))
	assert.Equal(t, kvClassOf("azure.vault_not_found"), kvClassOf("azure.unreachable"))
	assert.Equal(t, kvClassOf("azure.clock_skew"), kvClassOf("azure.auth_failed"))
	assert.Equal(t, classOther, kvClassOf("azure.unexpected_response"))
	assert.Equal(t, KVPollFailure{Object: "vault", Reason: reasonInternal}, sanitizeKVFailure("nonsense", nil))
	_ = providers.Warning{}
}
