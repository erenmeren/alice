package main

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckDirFindsAllProblemKinds(t *testing.T) {
	fsys := fstest.MapFS{
		"en.json": {Data: []byte(`{"a":"Hello {{name}}","b":"Bye","c":"Count {{n}}","d":""}`)},
		"tr.json": {Data: []byte(`{"a":"Merhaba {{isim}}","c":"Sayı {{n}}","d":"x","extra":"fazla"}`)},
	}
	problems, err := CheckDir(fsys, "en")
	require.NoError(t, err)
	assert.Equal(t, []Problem{
		{File: "en.json", Key: "d", Msg: "value is empty"},
		{File: "tr.json", Key: "a", Msg: "placeholders differ: en has [name], tr has [isim]"},
		{File: "tr.json", Key: "b", Msg: "missing key"},
		{File: "tr.json", Key: "extra", Msg: "key not present in en.json"},
	}, problems)
}

func TestCheckDirCleanCatalog(t *testing.T) {
	fsys := fstest.MapFS{
		"en.json": {Data: []byte(`{"a":{"b":"Hi {{name}}"}}`)},
		"tr.json": {Data: []byte(`{"a":{"b":"Selam {{name}}"}}`)},
	}
	problems, err := CheckDir(fsys, "en")
	require.NoError(t, err)
	assert.Empty(t, problems)
}

// i18n.T substitutes only {{name}}; a spaced placeholder would reach users verbatim.
func TestCheckDirRejectsPlaceholdersWithSpaces(t *testing.T) {
	fsys := fstest.MapFS{
		"en.json": {Data: []byte(`{"a":"Hi {{ name }}","b":"Bye {{who }}"}`)},
		"tr.json": {Data: []byte(`{"a":"Selam {{name}}","b":"Güle güle {{ who}}"}`)},
	}
	problems, err := CheckDir(fsys, "en")
	require.NoError(t, err)
	assert.Equal(t, []Problem{
		{File: "en.json", Key: "a", Msg: "placeholder must not contain spaces: {{ name }}"},
		{File: "en.json", Key: "b", Msg: "placeholder must not contain spaces: {{who }}"},
		{File: "tr.json", Key: "a", Msg: "placeholders differ: en has [], tr has [name]"},
		{File: "tr.json", Key: "b", Msg: "placeholder must not contain spaces: {{ who}}"},
	}, problems)
}

func TestCheckDirFlagsUntranslatedValuesUnlessAllowListed(t *testing.T) {
	fsys := fstest.MapFS{
		"en.json":              {Data: []byte(`{"app":"Alice","save":"Save","hello":"Hello {{name}}"}`)},
		"tr.json":              {Data: []byte(`{"app":"Alice","save":"Save","hello":"Hello {{name}}"}`)},
		".i18n-identical.json": {Data: []byte(`["app"]`)},
	}
	problems, err := CheckDir(fsys, "en")
	require.NoError(t, err)
	assert.Equal(t, []Problem{
		{File: "tr.json", Key: "hello", Msg: "value is identical to en; translate it or allow-list the key in .i18n-identical.json"},
		{File: "tr.json", Key: "save", Msg: "value is identical to en; translate it or allow-list the key in .i18n-identical.json"},
	}, problems)
}

func TestCheckDirRejectsMalformedAllowList(t *testing.T) {
	fsys := fstest.MapFS{
		"en.json":              {Data: []byte(`{"a":"x"}`)},
		".i18n-identical.json": {Data: []byte(`{"a":true}`)},
	}
	_, err := CheckDir(fsys, "en")
	assert.ErrorContains(t, err, ".i18n-identical.json")
}

func TestCheckDirRequiresSourceFile(t *testing.T) {
	_, err := CheckDir(fstest.MapFS{"tr.json": {Data: []byte(`{}`)}}, "en")
	assert.ErrorContains(t, err, "en.json")
}
