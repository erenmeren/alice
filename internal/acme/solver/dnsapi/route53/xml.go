package route53

import (
	"encoding/xml"
	"net/http"
	"regexp"
	"strings"

	"alice/internal/acme"
)

// apiNS is the XML namespace of the Route 53 API version this package speaks.
const apiNS = "https://route53.amazonaws.com/doc/2013-04-01/"

// changeComment is the comment of every change batch: it tells an administrator reading the zone's history where
// the change came from, and holds nothing of the order.
const changeComment = "alice acme dns-01"

// awsID is the shape of a hosted zone ID and a change ID. Both go into URL paths, so an answer's ID is checked
// before it is used: a value with "/", "?" or "%" could point a later request at another resource.
var awsID = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)

// The answers this package reads. Only the fields it uses are declared; encoding/xml matches local names, so the
// namespace of the answer does not matter. XMLName is checked by the caller: an answer of another shape (an HTML
// page from a proxy, an error document with a 2xx) is refused rather than read as empty.
type listZonesAnswer struct {
	XMLName xml.Name
	Zones   []struct {
		ID     string `xml:"Id"`
		Name   string `xml:"Name"`
		Config struct {
			PrivateZone string `xml:"PrivateZone"`
		} `xml:"Config"`
	} `xml:"HostedZones>HostedZone"`
}

type listSetsAnswer struct {
	XMLName xml.Name
	Sets    []struct {
		Name    string           `xml:"Name"`
		Type    string           `xml:"Type"`
		TTL     int              `xml:"TTL"`
		Records []resourceRecord `xml:"ResourceRecords>ResourceRecord"`
	} `xml:"ResourceRecordSets>ResourceRecordSet"`
}

type changeAnswer struct {
	XMLName xml.Name
	ID      string `xml:"ChangeInfo>Id"`
	Status  string `xml:"ChangeInfo>Status"`
}

// errorAnswer is AWS's error document: <ErrorResponse><Error><Type/><Code/><Message/></Error></ErrorResponse> (Route 53
// and STS), or Route 53's <InvalidChangeBatch><Messages>..</Messages></InvalidChangeBatch> for a refused change batch.
// The messages are never read: they repeat the request (names, values) and are AWS's text.
type errorAnswer struct {
	XMLName xml.Name
	Code    string `xml:"Error>Code"`
}

// The change batch this package sends.
type changeRequest struct {
	XMLName xml.Name `xml:"https://route53.amazonaws.com/doc/2013-04-01/ ChangeResourceRecordSetsRequest"`
	Comment string   `xml:"ChangeBatch>Comment"`
	Changes []change `xml:"ChangeBatch>Changes>Change"`
}

type change struct {
	Action string    `xml:"Action"`
	Set    txtSetXML `xml:"ResourceRecordSet"`
}

type txtSetXML struct {
	Name    string           `xml:"Name"`
	Type    string           `xml:"Type"`
	TTL     int              `xml:"TTL"`
	Records []resourceRecord `xml:"ResourceRecords>ResourceRecord"`
}

// resourceRecord is one <ResourceRecord><Value/></ResourceRecord>: every value has its own element (a slice tagged
// "ResourceRecords>ResourceRecord>Value" would put every value into one ResourceRecord).
type resourceRecord struct {
	Value string `xml:"Value"`
}

func toRecords(values []string) []resourceRecord {
	out := make([]resourceRecord, len(values))
	for i, v := range values {
		out[i].Value = v
	}
	return out
}

func fromRecords(rs []resourceRecord) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Value
	}
	return out
}

// Error codes that change how a failure is reported.
const (
	codeInvalidChangeBatch = "InvalidChangeBatch"
	codeNoSuchHostedZone   = "NoSuchHostedZone"
)

// errorCode is the AWS error code of an error answer ("" when the body is not one).
func errorCode(body []byte) string {
	var e errorAnswer
	if xml.Unmarshal(body, &e) != nil {
		return ""
	}
	if e.XMLName.Local == codeInvalidChangeBatch {
		return codeInvalidChangeBatch
	}
	if e.XMLName.Local != "ErrorResponse" || !plainCode(e.Code) {
		return ""
	}
	return e.Code
}

func plainCode(c string) bool {
	if c == "" || len(c) > 64 {
		return false
	}
	for i := 0; i < len(c); i++ {
		if !unreserved(c[i]) {
			return false
		}
	}
	return true
}

// throttled codes are AWS asking the caller to slow down (Route 53 answers them with HTTP 400): they are reported
// as a 429 so the order's failure is transient, as a rate limit is.
func throttled(code string) bool {
	switch code {
	case "Throttling", "ThrottlingException", "RequestThrottled", "PriorRequestNotComplete", "TooManyRequestsException":
		return true
	}
	return false
}

// authCode codes are a refused identity or signature, whatever status AWS sends them with.
func authCode(code string) bool {
	switch code {
	case "AccessDenied", "AccessDeniedException", "SignatureDoesNotMatch", "InvalidClientTokenId", "IncompleteSignature",
		"MissingAuthenticationToken", "ExpiredToken", "UnrecognizedClientException", "InvalidSignatureException":
		return true
	}
	return false
}

// apiError reports a Route 53 answer that is not a success. Only the status and the code are used.
func apiError(d string, status int, code string) *acme.Error {
	switch {
	case throttled(code):
		return acme.DNSProviderError(d, http.StatusTooManyRequests, false)
	case code == codeNoSuchHostedZone:
		return acme.DNSZoneNotFound(d)
	case authCode(code):
		return acme.DNSProviderError(d, http.StatusForbidden, false)
	}
	return acme.DNSProviderError(d, status, false)
}

// stsError reports an STS answer that is not a success: a refusal is a failed sign-in, a throttle and a server
// error are transient (acme.DNSSignInError).
func stsError(d string, status int, code string) *acme.Error {
	if throttled(code) {
		status = http.StatusTooManyRequests
	}
	return acme.DNSSignInError(d, status, false)
}

// quoteTXT is the Route 53 form of a TXT value: one or more quoted character strings of at most 255 bytes each,
// with '"' and '\' escaped. solver.PrintableValue guarantees visible ASCII.
func quoteTXT(v string) string {
	var parts []string
	for len(v) > 0 {
		n := min(len(v), 255)
		chunk := v[:n]
		v = v[n:]
		var b strings.Builder
		b.WriteByte('"')
		for i := 0; i < len(chunk); i++ {
			if chunk[i] == '"' || chunk[i] == '\\' {
				b.WriteByte('\\')
			}
			b.WriteByte(chunk[i])
		}
		b.WriteByte('"')
		parts = append(parts, b.String())
	}
	return strings.Join(parts, " ")
}

// unquoteTXT is the text of a Route 53 TXT value: its quoted character strings joined, escapes resolved (\" \\ and
// the \DDD octal form Route 53 uses for other bytes). A value that is not in quoted form is returned as it stands,
// so it never equals a value Alice publishes by accident of parsing.
func unquoteTXT(raw string) string {
	var b strings.Builder
	i := 0
	for i < len(raw) {
		for i < len(raw) && raw[i] == ' ' {
			i++
		}
		if i == len(raw) {
			break
		}
		if raw[i] != '"' {
			return raw
		}
		i++
		closed := false
		for i < len(raw) {
			c := raw[i]
			switch {
			case c == '"':
				closed = true
				i++
			case c == '\\' && i+3 < len(raw) && octal(raw[i+1]) && octal(raw[i+2]) && octal(raw[i+3]):
				b.WriteByte((raw[i+1]-'0')*64 + (raw[i+2]-'0')*8 + (raw[i+3] - '0'))
				i += 4
				continue
			case c == '\\' && i+1 < len(raw):
				b.WriteByte(raw[i+1])
				i += 2
				continue
			default:
				b.WriteByte(c)
				i++
				continue
			}
			break
		}
		if !closed {
			return raw
		}
	}
	return b.String()
}

func octal(c byte) bool { return c >= '0' && c <= '7' }
