package backup

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckCacheIsBounded(t *testing.T) {
	var c checkCache
	sig := fileSig{size: 1}
	for i := range maxCached {
		c.put(strconv.Itoa(i), sig, Info{Name: strconv.Itoa(i)})
	}
	assert.Len(t, c.entries, maxCached)
	c.put("0", sig, Info{Name: "again"})
	assert.Len(t, c.entries, maxCached, "replacing an entry does not grow the map")
	c.put("one more", sig, Info{})
	assert.Len(t, c.entries, 1, "a full cache starts over")
	_, ok := c.get("one more", fileSig{size: 2})
	assert.False(t, ok, "a different signature misses")
	c.retain(map[string]bool{})
	assert.Empty(t, c.entries)
}

func TestPartialName(t *testing.T) {
	for name, want := range map[string]bool{
		".alice-backup-ABCD1234-20260901T023000Z-auto.alicebak.partial":        true,
		".alice-backup-ABCD1234-20260901T023000Z-auto.alicebak.sha256.partial": true,
		".mine.alicebak.partial":       true,
		"mine.alicebak.partial":        false,
		".notes.partial":               false,
		".mine.alicebak":               false,
		"..mine.alicebak.partial":      false,
		".a/b.alicebak.partial":        false,
		".mine.alicebak.sha256":        false,
		".mine.alicebak.partial.extra": false,
	} {
		assert.Equal(t, want, partialName(name), name)
	}
}
