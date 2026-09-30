package i18n_test

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/locales"
)

func fixture() fstest.MapFS {
	return fstest.MapFS{
		"manifest.json":  {Data: []byte(`{"default":"en","locales":[{"code":"tr","name":"Türkçe","direction":"ltr"},{"code":"en","name":"English","direction":"ltr"}]}`)},
		"common/en.json": {Data: []byte(`{"greet":{"hello":"Hello {{name}}"},"only_en":"English only"}`)},
		"common/tr.json": {Data: []byte(`{"greet":{"hello":"Merhaba {{name}}"}}`)},
	}
}

func TestTranslateWithParamsAndFallback(t *testing.T) {
	c, err := i18n.Load(fixture())
	require.NoError(t, err)
	assert.Equal(t, "Merhaba İzmir", c.T("tr", "greet.hello", map[string]string{"name": "İzmir"}))
	assert.Equal(t, "Hello Ada", c.T("en", "greet.hello", map[string]string{"name": "Ada"}))
	assert.Equal(t, "English only", c.T("tr", "only_en", nil), "missing Turkish key falls back to English")
	assert.Equal(t, "missing.key", c.T("tr", "missing.key", nil), "unknown key returns the key")
	assert.Equal(t, "Hello Ada", c.T("de", "greet.hello", map[string]string{"name": "Ada"}), "unknown language uses default")
}

func TestNegotiate(t *testing.T) {
	c, err := i18n.Load(fixture())
	require.NoError(t, err)
	assert.Equal(t, "en", c.Default())
	cases := map[string]string{
		"":                         "en",
		"tr-TR,tr;q=0.9,en;q=0.8":  "tr",
		"TR":                       "tr",
		"de-DE,de;q=0.9":           "en",
		"de-DE,tr;q=0.5":           "tr",
		"en-GB":                    "en",
		"this is ;;; not a header": "en",
	}
	for header, want := range cases {
		assert.Equal(t, want, c.Negotiate(header), "header %q", header)
	}
}

func TestLocalesKeepManifestOrder(t *testing.T) {
	c, err := i18n.Load(fixture())
	require.NoError(t, err)
	require.Len(t, c.Locales(), 2)
	assert.Equal(t, "tr", c.Locales()[0].Code)
	assert.Equal(t, "Türkçe", c.Locales()[0].Name)
}

func TestLoadErrors(t *testing.T) {
	bad := fixture()
	bad["common/tr.json"] = &fstest.MapFile{Data: []byte(`{"greet":{"hello":3}}`)}
	_, err := i18n.Load(bad)
	assert.ErrorContains(t, err, "greet.hello")

	missing := fixture()
	delete(missing, "common/tr.json")
	_, err = i18n.Load(missing)
	assert.ErrorContains(t, err, "common/tr.json")

	noDefault := fixture()
	noDefault["manifest.json"] = &fstest.MapFile{Data: []byte(`{"default":"fr","locales":[{"code":"en","name":"English","direction":"ltr"}]}`)}
	_, err = i18n.Load(noDefault)
	assert.ErrorContains(t, err, "default")
}

func TestFlatten(t *testing.T) {
	m, err := i18n.Flatten([]byte(`{"a":{"b":"x","c":{"d":"y"}},"e":"z"}`))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a.b": "x", "a.c.d": "y", "e": "z"}, m)
}

func TestRealCatalogLoads(t *testing.T) {
	c, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	assert.Equal(t, "Alice", c.T("tr", "app.name", nil))
	assert.NotEqual(t, "errors.system.not_found.title", c.T("tr", "errors.system.not_found.title", nil))
	assert.Equal(t, "tr", c.Negotiate("tr-TR,tr;q=0.9,en;q=0.8"), "a Turkish browser must get Turkish")
}
