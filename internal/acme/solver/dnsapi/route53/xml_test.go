package route53

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuoteTXT(t *testing.T) {
	assert.Equal(t, `"abc"`, quoteTXT("abc"))
	assert.Equal(t, `"a\"b\\c"`, quoteTXT(`a"b\c`))
	long := quoteTXT(strings.Repeat("a", 256))
	assert.Equal(t, `"`+strings.Repeat("a", 255)+`" "a"`, long)
	assert.Empty(t, quoteTXT(""))
}

func TestUnquoteTXT(t *testing.T) {
	for raw, want := range map[string]string{
		`"abc"`:                  "abc",
		`"a" "b"`:                "ab",
		` "a"  "b" `:             "ab",
		`"a\"b\\c"`:              `a"b\c`,
		`"\052x"`:                "*x",
		`"\0"`:                   "0",
		`abc`:                    "abc",
		`"abc`:                   `"abc`,
		`"a" b`:                  `"a" b`,
		`"a\`:                    `"a\`,
		strings.Repeat(`"x"`, 3): "xxx",
	} {
		assert.Equal(t, want, unquoteTXT(raw), raw)
	}
	for _, v := range []string{"abc", `a"b\c`, strings.Repeat("z", 600)} {
		assert.Equal(t, v, unquoteTXT(quoteTXT(v)), "round trip")
	}
}

func TestErrorCode(t *testing.T) {
	for body, want := range map[string]string{
		`<ErrorResponse xmlns="x"><Error><Type>Sender</Type><Code>Throttling</Code><Message>m</Message></Error></ErrorResponse>`: "Throttling",
		`<InvalidChangeBatch><Messages><Message>m</Message></Messages></InvalidChangeBatch>`:                                     codeInvalidChangeBatch,
		`<ErrorResponse><Error><Code></Code></Error></ErrorResponse>`:                                                            "",
		`<ErrorResponse><Error><Code>` + strings.Repeat("A", 65) + `</Code></Error></ErrorResponse>`:                             "",
		`<Other><Error><Code>Throttling</Code></Error></Other>`:                                                                  "",
		`not xml`: "",
	} {
		assert.Equal(t, want, errorCode([]byte(body)), body)
	}
}

func TestChangeRequestShape(t *testing.T) {
	out, err := xml.Marshal(changeRequest{Comment: changeComment, Changes: []change{{Action: "UPSERT",
		Set: txtSetXML{Name: "_acme-challenge.example.com.", Type: "TXT", TTL: 60, Records: toRecords([]string{`"a"`, `"b"`})}}}})
	require.NoError(t, err)
	assert.Equal(t, `<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch>`+
		`<Comment>alice acme dns-01</Comment><Changes><Change><Action>UPSERT</Action><ResourceRecordSet>`+
		`<Name>_acme-challenge.example.com.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords>`+
		`<ResourceRecord><Value>&#34;a&#34;</Value></ResourceRecord><ResourceRecord><Value>&#34;b&#34;</Value></ResourceRecord>`+
		`</ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`, string(out))
}
