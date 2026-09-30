package validate_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/platform/validate"
	"alice/locales"
)

func TestErrorsCollectAndSurviveWrapping(t *testing.T) {
	var v validate.Errors
	require.NoError(t, v.Err())

	v.Add("username", validate.Pattern, nil)
	v.Add("display_name", validate.TooLong, map[string]string{"max": "100"})
	err := fmt.Errorf("create user: %w", v.Err())

	var got validate.Errors
	require.True(t, errors.As(err, &got))
	assert.Equal(t, validate.Errors{
		{Field: "username", Code: "validation.pattern"},
		{Field: "display_name", Code: "validation.too_long", Params: map[string]string{"max": "100"}},
	}, got)
	assert.Equal(t, "validation failed: username validation.pattern; display_name validation.too_long", got.Error())
}

func TestCodesAreLocaleKeys(t *testing.T) {
	for _, c := range []string{validate.Required, validate.TooShort, validate.TooLong, validate.Pattern,
		validate.OneOf, validate.OutOfRange, validate.Email} {
		assert.Regexp(t, `^validation\.[a-z_]+$`, c)
	}
}

func TestEveryCodeIsTranslated(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for _, c := range []string{validate.Required, validate.TooShort, validate.TooLong, validate.Pattern,
		validate.OneOf, validate.OutOfRange, validate.Email} {
		for _, lang := range []string{"en", "tr"} {
			assert.NotEqual(t, c, cat.T(lang, c, nil), "missing %s in %s", c, lang)
		}
	}
}
