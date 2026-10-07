package claims

import (
	"testing"
	"time"
)

// FuzzParse: any payload either parses or is refused as malformed; parsing never panics, and Validate and Groups
// never panic on what Parse accepts.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"iss":"https://idp","aud":["alice"],"sub":"s","exp":1790000000,"iat":1790000000,"nonce":"n","groups":["a"]}`))
	f.Add([]byte(`{"aud":"alice","_claim_names":{"groups":"s"},"hasgroups":true}`))
	f.Add([]byte(`{"groups":"one","exp":1.5e9}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Parse(b)
		if err != nil {
			return
		}
		_ = Validate(c, Expect{Issuer: "https://idp", ClientID: "alice", Nonce: "n", Now: time.Unix(1790000000, 0), MaxAuthAge: time.Minute})
		_, _ = Groups(c, "groups")
		_ = Username(c)
	})
}
