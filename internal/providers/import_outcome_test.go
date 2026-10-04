package providers_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
)

// TestImportResultRules is the table of every legal and illegal shape of an import: what the
// provider returned (ImportResult and error) against what CheckImportReturn accepts.
func TestImportResultRules(t *testing.T) {
	v, cer := strings.Repeat("a", 32), []byte{1}
	tp := azureid.ThumbprintOf(cer)
	created := providers.ImportResult{Outcome: providers.ImportCreated, Version: v, Thumbprint: tp, CER: cer}
	refusal := providers.NewError("azure.forbidden", false, nil, nil)
	cases := []struct {
		name string
		r    providers.ImportResult
		err  error
		ok   bool
	}{
		// created: the vault answered with the new version, nothing else.
		{"created", created, nil, true},
		{"created with an error", created, refusal, false},
		{"created with a plain error", created, errors.New("x"), false},
		{"created without a version", providers.ImportResult{Outcome: providers.ImportCreated, Thumbprint: tp, CER: []byte{1}}, nil, false},
		{"created with an upper-case version", providers.ImportResult{Outcome: providers.ImportCreated, Version: strings.Repeat("A", 32), Thumbprint: tp, CER: []byte{1}}, nil, false},
		{"created without a thumbprint", providers.ImportResult{Outcome: providers.ImportCreated, Version: v, CER: []byte{1}}, nil, false},
		{"created with a bad thumbprint", providers.ImportResult{Outcome: providers.ImportCreated, Version: v, Thumbprint: "x", CER: []byte{1}}, nil, false},
		{"created with another leaf's thumbprint", providers.ImportResult{Outcome: providers.ImportCreated, Version: v, Thumbprint: strings.Repeat("b", 40), CER: []byte{1}}, nil, false},
		{"created without the leaf", providers.ImportResult{Outcome: providers.ImportCreated, Version: v, Thumbprint: tp}, nil, false},
		// refused: nothing changed; only a well-formed refusal (*Error) that is no transport failure.
		{"refused", providers.ImportResult{Outcome: providers.ImportRefused}, refusal, true},
		{"refused with a wrapped provider error", providers.ImportResult{Outcome: providers.ImportRefused}, fmt.Errorf("x: %w", refusal), true},
		{"refused with a cause that is not a transport failure", providers.ImportResult{Outcome: providers.ImportRefused},
			providers.NewError("azure.forbidden", false, errors.New("403"), nil), true},
		{"refused without a provider error", providers.ImportResult{Outcome: providers.ImportRefused}, errors.New("x"), false},
		{"refused with a nil error", providers.ImportResult{Outcome: providers.ImportRefused}, nil, false},
		{"refused with a version", providers.ImportResult{Outcome: providers.ImportRefused, Version: v}, refusal, false},
		{"refused with a thumbprint", providers.ImportResult{Outcome: providers.ImportRefused, Thumbprint: tp}, refusal, false},
		{"refused with a leaf", providers.ImportResult{Outcome: providers.ImportRefused, CER: []byte{1}}, refusal, false},
		{"refused by a timeout", providers.ImportResult{Outcome: providers.ImportRefused},
			providers.NewError("azure.unreachable", true, context.DeadlineExceeded, nil), false},
		{"refused by a cancelled request", providers.ImportResult{Outcome: providers.ImportRefused},
			providers.NewError("azure.unreachable", true, context.Canceled, nil), false},
		{"refused by a network error", providers.ImportResult{Outcome: providers.ImportRefused},
			providers.NewError("azure.unreachable", true, &net.OpError{Op: "read", Err: errors.New("reset")}, nil), false},
		{"refused by an unexpected end of the answer", providers.ImportResult{Outcome: providers.ImportRefused},
			providers.NewError("azure.unexpected_response", true, io.ErrUnexpectedEOF, nil), false},
		{"refused by a closed connection", providers.ImportResult{Outcome: providers.ImportRefused},
			providers.NewError("azure.unreachable", true, io.EOF, nil), false},
		// uncertain: the request may have reached the vault; an error says why.
		{"uncertain", providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("timeout"), true},
		{"uncertain with a provider error", providers.ImportResult{Outcome: providers.ImportUncertain},
			providers.NewError("azure.unreachable", true, context.DeadlineExceeded, nil), true},
		{"uncertain without an error", providers.ImportResult{Outcome: providers.ImportUncertain}, nil, false},
		{"uncertain with a leaf", providers.ImportResult{Outcome: providers.ImportUncertain, CER: []byte{1}}, errors.New("x"), false},
		{"uncertain with a version", providers.ImportResult{Outcome: providers.ImportUncertain, Version: v}, errors.New("x"), false},
		// anything else.
		{"blank", providers.ImportResult{}, nil, false},
		{"blank with an error", providers.ImportResult{}, errors.New("x"), false},
		{"unknown", providers.ImportResult{Outcome: "maybe"}, nil, false},
		{"unknown with an error", providers.ImportResult{Outcome: "no_change"}, refusal, false},
		{"unsupported", providers.ImportResult{}, providers.ErrUnsupported, false},
		{"unsupported with an outcome", providers.ImportResult{Outcome: providers.ImportRefused}, providers.ErrUnsupported, false},
	}
	for _, tc := range cases {
		err := providers.CheckImportReturn(tc.r, tc.err)
		if tc.ok {
			assert.NoError(t, err, tc.name)
		} else {
			assert.Error(t, err, tc.name)
		}
	}
}

func TestImportResultValidateAloneKnowsNothingOfTheError(t *testing.T) {
	v, tp := strings.Repeat("0", 32), azureid.ThumbprintOf([]byte{1})
	require.NoError(t, providers.ImportResult{Outcome: providers.ImportCreated, Version: v, Thumbprint: tp, CER: []byte{1}}.Validate())
	require.NoError(t, providers.ImportResult{Outcome: providers.ImportRefused}.Validate())
	require.NoError(t, providers.ImportResult{Outcome: providers.ImportUncertain}.Validate())
	err := providers.ImportResult{}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `blank or unknown outcome "blank"`)
	err = providers.ImportResult{Outcome: "maybe"}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"maybe"`)
}

func TestImportOutcomeConstantsAreTheClosedSet(t *testing.T) {
	assert.Equal(t, "created", providers.ImportCreated)
	assert.Equal(t, "refused", providers.ImportRefused)
	assert.Equal(t, "uncertain", providers.ImportUncertain)
}
