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
		"en.json": {Data: []byte(`{"a":{"b":"Hi {{ name }}"}}`)},
		"tr.json": {Data: []byte(`{"a":{"b":"Selam {{name}}"}}`)},
	}
	problems, err := CheckDir(fsys, "en")
	require.NoError(t, err)
	assert.Empty(t, problems)
}

func TestCheckDirRequiresSourceFile(t *testing.T) {
	_, err := CheckDir(fstest.MapFS{"tr.json": {Data: []byte(`{}`)}}, "en")
	assert.ErrorContains(t, err, "en.json")
}
