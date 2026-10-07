package alerts

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTemplateNamesAreValid(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`) // notify's templatePattern
	assert.Len(t, Templates(), 9)
	for _, tpl := range Templates() {
		assert.Regexp(t, pattern, tpl)
	}
	assert.Equal(t, []Kind{KindCertificate, KindKVCertificate, KindKVKey, KindKVCredential}, Kinds())
}
