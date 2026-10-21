package fakeroute53

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const stsNS = "https://sts.amazonaws.com/doc/2011-06-15/"

var sessionNamePattern = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{2,64}$`)

// serveSTS verifies the signature, then answers AssumeRole (or its scripted fault).
func (s *Server) serveSTS(w http.ResponseWriter, r *http.Request, op string, body []byte) {
	who, aerr := s.verify(r, body, "sts")
	if aerr != nil {
		s.count("auth-failed")
		writeError(w, stsNS, aerr.status, aerr.code)
		return
	}
	if op == "" {
		writeError(w, stsNS, http.StatusBadRequest, "InvalidAction")
		return
	}
	s.withFault(w, r, op, stsNS, func() {
		form, err := url.ParseQuery(string(body))
		if err != nil {
			writeError(w, stsNS, http.StatusBadRequest, "MalformedQueryString")
			return
		}
		s.assumeRole(w, form, who)
	})
}

type assumeRoleXML struct {
	XMLName         xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleResponse"`
	AssumedRoleID   string   `xml:"AssumeRoleResult>AssumedRoleUser>AssumedRoleId"`
	AssumedRoleARN  string   `xml:"AssumeRoleResult>AssumedRoleUser>Arn"`
	AccessKeyID     string   `xml:"AssumeRoleResult>Credentials>AccessKeyId"`
	SecretAccessKey string   `xml:"AssumeRoleResult>Credentials>SecretAccessKey"`
	SessionToken    string   `xml:"AssumeRoleResult>Credentials>SessionToken"`
	Expiration      string   `xml:"AssumeRoleResult>Credentials>Expiration"`
	RequestID       string   `xml:"ResponseMetadata>RequestId"`
}

// assumeRole is STS AssumeRole for Options.RoleARN, granted to the long-term key only (no role chaining).
func (s *Server) assumeRole(w http.ResponseWriter, form url.Values, who signer) {
	if form.Get("Action") != "AssumeRole" || form.Get("Version") != "2011-06-15" {
		writeError(w, stsNS, http.StatusBadRequest, "InvalidAction")
		return
	}
	duration := 3600
	if v := form.Get("DurationSeconds"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 900 || n > 43200 {
			writeError(w, stsNS, http.StatusBadRequest, "ValidationError")
			return
		}
		duration = n
	}
	name := form.Get("RoleSessionName")
	if !sessionNamePattern.MatchString(name) || form.Get("RoleArn") == "" {
		writeError(w, stsNS, http.StatusBadRequest, "ValidationError")
		return
	}
	if who.temp || s.o.RoleARN == "" || form.Get("RoleArn") != s.o.RoleARN ||
		(s.o.ExternalID != "" && form.Get("ExternalId") != s.o.ExternalID) {
		s.count("auth-failed")
		writeError(w, stsNS, http.StatusForbidden, "AccessDenied")
		return
	}
	exp := s.now().UTC().Add(time.Duration(duration) * time.Second).Truncate(time.Second)
	c := Credentials{AccessKeyID: "ASIA" + randomUpper(16), SecretAccessKey: randomSecret(30), SessionToken: randomSecret(300), Expiration: exp}
	roleName := s.o.RoleARN[strings.LastIndex(s.o.RoleARN, "/")+1:]
	account := "000000000000"
	if parts := strings.Split(s.o.RoleARN, ":"); len(parts) > 4 {
		account = parts[4]
	}
	s.mu.Lock()
	s.temps[c.AccessKeyID] = c
	s.sessions = append(s.sessions, Session{RoleSessionName: name, DurationSeconds: duration, ExternalID: form.Get("ExternalId")})
	s.mu.Unlock()
	s.count(OpAssumeRole)
	writeXML(w, http.StatusOK, assumeRoleXML{
		AssumedRoleID: "AROA" + randomUpper(17) + ":" + name, AssumedRoleARN: "arn:aws:sts::" + account + ":assumed-role/" + roleName + "/" + name,
		AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken,
		Expiration: exp.Format(time.RFC3339), RequestID: randomUpper(20),
	})
}
