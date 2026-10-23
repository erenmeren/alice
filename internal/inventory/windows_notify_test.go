package inventory

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/providers"
)

// The previous certificate a Windows deployment's e-mail names (R61): store \ thumbprint, else the thumbprint, else
// the DER SHA-256 the start record keeps, else "-"; a value outside its rule is left out.
func TestPreviousCertificateText(t *testing.T) {
	const sha1, sha256 = "0123456789abcdef0123456789abcdef01234567", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	op := uuid.New()
	for name, tc := range map[string]struct {
		ref  *providers.BackupRef
		want string
	}{
		"store and thumbprint": {&providers.BackupRef{OperationID: op, Store: "MY", PreviousSHA1: sha1, PreviousSHA256: sha256}, `MY \ ` + sha1},
		"web hosting":          {&providers.BackupRef{Store: "WebHosting", PreviousSHA1: sha1}, `WebHosting \ ` + sha1},
		"thumbprint only":      {&providers.BackupRef{PreviousSHA1: sha1, PreviousSHA256: sha256}, sha1},
		"SHA-256 only":         {&providers.BackupRef{OperationID: op, PreviousSHA256: sha256}, "SHA-256 " + sha256},
		"bad store":            {&providers.BackupRef{Store: "MY\r\nBcc: x", PreviousSHA1: sha1}, sha1},
		"my, any case":         {&providers.BackupRef{Store: "my", PreviousSHA1: sha1}, `my \ ` + sha1},
		// W2 final review Minor 3: the API's rule (My or WebHosting), not the record's looser store rule.
		"another store":  {&providers.BackupRef{Store: "Remote Desktop", PreviousSHA1: sha1}, sha1},
		"a long store":   {&providers.BackupRef{Store: "Please call 555-0100 about this certificate", PreviousSHA1: sha1}, sha1},
		"bad thumbprint": {&providers.BackupRef{Store: "MY", PreviousSHA1: "0123456789ABCDEF0123456789ABCDEF01234567", PreviousSHA256: sha256}, "SHA-256 " + sha256},
		"bad SHA-256":    {&providers.BackupRef{PreviousSHA256: "x"}, "-"},
		"a Linux backup": {&providers.BackupRef{OperationID: op, Dir: BackupRoot + "/" + op.String()}, "-"},
		"none":           {nil, "-"},
	} {
		assert.Equal(t, tc.want, previousCertificate(tc.ref), name)
	}
	assert.Equal(t, "deployment.failed_windows", WindowsTemplate(TemplateDeploymentFailed))
}
