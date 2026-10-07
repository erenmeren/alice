package fakeidp

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"time"
)

// idToken builds the ID token of g with the current fault. The caller holds s.mu.
func (s *Server) idToken(g *grant) (string, error) {
	if len(s.keys) == 0 {
		return "", errNoKey
	}
	f, l, now := s.fault, g.login, s.opts.Now()
	expIn := 5 * time.Minute
	if f.ExpIn != 0 {
		expIn = f.ExpIn
	}
	claims := map[string]any{"iss": s.issuer, "aud": s.clientID, "sub": l.Subject, "nonce": g.nonce,
		"exp": now.Add(expIn).Unix(), "iat": now.Add(f.IatOffset).Unix(), "auth_time": g.authTime.Add(-f.AuthTimeAgo).Unix()}
	for k, v := range map[string]string{"email": l.Email, "name": l.Name, "preferred_username": l.Username} {
		if v != "" {
			claims[k] = v
		}
	}
	if f.HasGroups {
		claims["hasgroups"] = true
	} else if f.Overage {
		claims["_claim_names"] = map[string]string{"groups": "src1"}
		claims["_claim_sources"] = map[string]any{"src1": map[string]string{"endpoint": "https://graph.microsoft.com/v1.0/users/" + l.Subject + "/getMemberObjects"}}
	} else if l.Groups != nil {
		claims["groups"] = l.Groups
	}
	for k, v := range l.Extra {
		claims[k] = v
	}
	if f.Issuer != "" {
		claims["iss"] = f.Issuer
	}
	switch len(f.Audience) {
	case 0:
	case 1:
		claims["aud"] = f.Audience[0]
	default:
		claims["aud"] = f.Audience
	}
	if f.Azp != "" {
		claims["azp"] = f.Azp
	}
	if f.NbfOffset != 0 {
		claims["nbf"] = now.Add(f.NbfOffset).Unix()
	}
	if f.Nonce != nil {
		claims["nonce"] = *f.Nonce
	}
	if f.OmitNonce {
		delete(claims, "nonce")
	}
	if f.OmitAuthTime {
		delete(claims, "auth_time")
	}
	signer := s.keys[len(s.keys)-1]
	alg, kid := "RS256", signer.kid
	if f.Alg != "" {
		alg = f.Alg
	}
	if f.UnknownKid {
		kid = "unknown"
	}
	if f.Kid != "" {
		kid = f.Kid
	}
	hdr, err := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(hdr) + "." + b64(body)
	switch alg {
	case "none":
		return input + ".", nil
	case "HS256":
		pub, err := x509.MarshalPKIXPublicKey(&signer.key.PublicKey)
		if err != nil {
			return "", err
		}
		mac := hmac.New(sha256.New, pub) // algorithm confusion: the public key as the HMAC secret (O-01)
		mac.Write([]byte(input))
		return input + "." + b64(mac.Sum(nil)), nil
	}
	key := signer.key
	if f.OtherKey {
		if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			return "", err
		}
	}
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}
