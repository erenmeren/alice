package dnsapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInZoneAndCandidates(t *testing.T) {
	assert.True(t, InZone("a.example.com", "example.com"))
	assert.True(t, InZone("example.com", "example.com"))
	assert.False(t, InZone("badexample.com", "example.com"))
	assert.False(t, InZone("example.com", ""))
	assert.Equal(t, []string{"_acme-challenge.www.example.com", "www.example.com", "example.com"},
		Candidates("_acme-challenge.www.example.com"))
	assert.Equal(t, []string{"example.com"}, Candidates("example.com"))
	assert.Empty(t, Candidates("com"))
}

func TestLongest(t *testing.T) {
	zones := []Zone{{Name: "Example.com.", ID: "1"}, {Name: "www.example.com", ID: "2"}, {Name: "ample.com", ID: "3"},
		{Name: "bad_zone.example.com", ID: "4"}, {Name: "com", ID: "5"}}
	z, ok := Longest("_acme-challenge.www.example.com", zones)
	assert.True(t, ok)
	assert.Equal(t, Zone{Name: "www.example.com", ID: "2"}, z)
	z, ok = Longest("_acme-challenge.api.example.com", zones)
	assert.True(t, ok)
	assert.Equal(t, Zone{Name: "example.com", ID: "1"}, z)
	_, ok = Longest("_acme-challenge.other.test", zones)
	assert.False(t, ok)
	// A delegated challenge zone wins over its parent.
	z, ok = Longest("_acme-challenge.example.com", append(zones, Zone{Name: "_acme-challenge.example.com", ID: "6"}))
	assert.True(t, ok)
	assert.Equal(t, "6", z.ID)
}

func TestNormalizeZoneName(t *testing.T) {
	for in, want := range map[string]string{"Example.COM.": "example.com", "_acme-challenge.example.com": "_acme-challenge.example.com"} {
		got, ok := NormalizeZoneName(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got)
	}
	for _, in := range []string{"com", "*.example.com", "a_b.example.com", "", "_acme-challenge.com", "ex ample.com", "x..y"} {
		_, ok := NormalizeZoneName(in)
		assert.False(t, ok, in)
	}
}

func TestRelativeName(t *testing.T) {
	assert.Equal(t, "@", RelativeName("example.com", "example.com"))
	assert.Equal(t, "_acme-challenge.www", RelativeName("_acme-challenge.www.example.com", "example.com"))
}
