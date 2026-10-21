package fakeroute53

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	r53NS                  = "https://route53.amazonaws.com/doc/2013-04-01/"
	codeInvalidChangeBatch = "InvalidChangeBatch"
	maxTTL                 = 2147483647
)

// serveRoute53 verifies the signature, then answers the operation (or its scripted fault).
func (s *Server) serveRoute53(w http.ResponseWriter, r *http.Request, op string, body []byte) {
	who, aerr := s.verify(r, body, "route53")
	if aerr == nil && s.o.RoleARN != "" && !who.temp {
		// With a role configured, the fake's account grants Route 53 to the role only (Options.RoleARN).
		aerr = &authError{status: http.StatusForbidden, code: "AccessDenied"}
	}
	if aerr != nil {
		s.count("auth-failed")
		writeError(w, r53NS, aerr.status, aerr.code)
		return
	}
	if op == "" {
		writeError(w, r53NS, http.StatusNotFound, "UnknownOperation") // GUESS: the reference does not say
		return
	}
	s.withFault(w, r, op, r53NS, func() {
		switch op {
		case OpZones:
			s.listZones(w, r.URL.Query())
		case OpList:
			s.listSets(w, pathPart(r.URL.Path, 2), r.URL.Query())
		case OpChange:
			s.changeSets(w, pathPart(r.URL.Path, 2), body)
		default:
			s.getChange(w, pathPart(r.URL.Path, 2))
		}
	})
}

// pathPart is the i-th segment of /2013-04-01/a/b/c (1-based after the version).
func pathPart(p string, i int) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if i < len(parts) {
		return parts[i]
	}
	return ""
}

type hostedZoneXML struct {
	ID              string `xml:"Id"`
	Name            string `xml:"Name"`
	CallerReference string `xml:"CallerReference"`
	Config          struct {
		PrivateZone bool `xml:"PrivateZone"`
	} `xml:"Config"`
	ResourceRecordSetCount int `xml:"ResourceRecordSetCount"`
}

type listZonesXML struct {
	XMLName          xml.Name        `xml:"https://route53.amazonaws.com/doc/2013-04-01/ ListHostedZonesByNameResponse"`
	HostedZones      []hostedZoneXML `xml:"HostedZones>HostedZone"`
	DNSName          string          `xml:"DNSName,omitempty"`
	IsTruncated      bool            `xml:"IsTruncated"`
	NextDNSName      string          `xml:"NextDNSName,omitempty"`
	NextHostedZoneID string          `xml:"NextHostedZoneId,omitempty"`
	MaxItems         int             `xml:"MaxItems"`
}

// listZones is ListHostedZonesByName: the zones in Route 53's order (labels reversed, then ID) from dnsname on.
func (s *Server) listZones(w http.ResponseWriter, q url.Values) {
	dnsName := normName(q.Get("dnsname"))
	maxItems, ok := itemsParam(q.Get("maxitems"), 100)
	if !ok || (q.Get("hostedzoneid") != "" && dnsName == "") {
		writeError(w, r53NS, http.StatusBadRequest, "InvalidInput")
		return
	}
	if dnsName != "" && !dnsChars(dnsName) {
		writeError(w, r53NS, http.StatusBadRequest, "InvalidDomainName")
		return
	}
	s.mu.Lock()
	zones := append([]*zone(nil), s.zones...)
	out := listZonesXML{DNSName: q.Get("dnsname"), MaxItems: maxItems}
	sort.SliceStable(zones, func(i, j int) bool {
		ki, kj := reverseKey(zones[i].name), reverseKey(zones[j].name)
		if ki != kj {
			return ki < kj
		}
		return zones[i].id < zones[j].id
	})
	start := reverseKey(dnsName)
	for _, z := range zones {
		if dnsName != "" && reverseKey(z.name) < start {
			continue
		}
		if len(out.HostedZones) == maxItems {
			out.IsTruncated, out.NextDNSName, out.NextHostedZoneID = true, z.name+".", z.id
			break
		}
		hz := hostedZoneXML{ID: "/hostedzone/" + z.id, Name: z.name + ".", CallerReference: "fake-" + z.id, ResourceRecordSetCount: len(z.sets)}
		hz.Config.PrivateZone = z.private
		out.HostedZones = append(out.HostedZones, hz)
	}
	s.mu.Unlock()
	s.count(OpZones)
	writeXML(w, http.StatusOK, out)
}

type rrsetXML struct {
	Name    string      `xml:"Name"`
	Type    string      `xml:"Type"`
	TTL     *int        `xml:"TTL"`
	Records []recordXML `xml:"ResourceRecords>ResourceRecord"`
}

// recordXML is one ResourceRecord: exactly one Value (a change with several Values in one ResourceRecord is
// refused InvalidInput: the schema allows one).
type recordXML struct {
	Values []string `xml:"Value"`
}

func records(values []string) []recordXML {
	out := make([]recordXML, len(values))
	for i, v := range values {
		out[i].Values = []string{v}
	}
	return out
}

// flatValues flattens a request's records; false when a record does not hold exactly one value.
func flatValues(rs []recordXML) ([]string, bool) {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		if len(r.Values) != 1 {
			return nil, false
		}
		out = append(out, r.Values[0])
	}
	return out, true
}

type listSetsXML struct {
	XMLName        xml.Name   `xml:"https://route53.amazonaws.com/doc/2013-04-01/ ListResourceRecordSetsResponse"`
	Sets           []rrsetXML `xml:"ResourceRecordSets>ResourceRecordSet"`
	IsTruncated    bool       `xml:"IsTruncated"`
	NextRecordName string     `xml:"NextRecordName,omitempty"`
	NextRecordType string     `xml:"NextRecordType,omitempty"`
	MaxItems       int        `xml:"MaxItems"`
}

// listSets is ListResourceRecordSets: the zone's sets in Route 53's order (labels reversed, then type) from name
// and type on. When there is no set at the name and type asked, the next one in that order is answered, as AWS does.
func (s *Server) listSets(w http.ResponseWriter, zoneID string, q url.Values) {
	name, typ := normName(q.Get("name")), q.Get("type")
	maxItems, ok := itemsParam(q.Get("maxitems"), 300)
	if !ok || (typ != "" && name == "") || (typ != "" && !validType(typ)) {
		writeError(w, r53NS, http.StatusBadRequest, "InvalidInput")
		return
	}
	s.mu.Lock()
	z := s.zoneLocked(zoneID)
	if z == nil {
		s.mu.Unlock()
		writeError(w, r53NS, http.StatusNotFound, "NoSuchHostedZone")
		return
	}
	names := make([]string, 0, len(z.sets))
	for n := range z.sets {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return reverseKey(names[i]) < reverseKey(names[j]) })
	out := listSetsXML{MaxItems: maxItems}
	for _, n := range names {
		if name != "" && (reverseKey(n) < reverseKey(name) || (n == name && "TXT" < typ)) {
			continue
		}
		if len(out.Sets) == maxItems {
			out.IsTruncated, out.NextRecordName, out.NextRecordType = true, n+".", "TXT"
			break
		}
		set := z.sets[n]
		ttl := set.ttl
		out.Sets = append(out.Sets, rrsetXML{Name: n + ".", Type: "TXT", TTL: &ttl, Records: records(set.values)})
	}
	s.mu.Unlock()
	s.count(OpList)
	writeXML(w, http.StatusOK, out)
}

type changeRequestXML struct {
	XMLName xml.Name
	Comment string `xml:"ChangeBatch>Comment"`
	Changes []struct {
		Action string   `xml:"Action"`
		Set    rrsetXML `xml:"ResourceRecordSet"`
	} `xml:"ChangeBatch>Changes>Change"`
}

type changeInfoXML struct {
	ID          string `xml:"Id"`
	Status      string `xml:"Status"`
	SubmittedAt string `xml:"SubmittedAt"`
	Comment     string `xml:"Comment,omitempty"`
}

type changeResponseXML struct {
	XMLName    xml.Name
	ChangeInfo changeInfoXML `xml:"ChangeInfo"`
}

// changeSets is ChangeResourceRecordSets: every change of the batch applies, or none (InvalidChangeBatch).
func (s *Server) changeSets(w http.ResponseWriter, zoneID string, body []byte) {
	var req changeRequestXML
	if xml.Unmarshal(body, &req) != nil || req.XMLName.Space != r53NS || req.XMLName.Local != "ChangeResourceRecordSetsRequest" ||
		len(req.Changes) == 0 || len(req.Changes) > 1000 {
		writeError(w, r53NS, http.StatusBadRequest, "InvalidInput")
		return
	}
	s.mu.Lock()
	z := s.zoneLocked(zoneID)
	if z == nil {
		s.mu.Unlock()
		writeError(w, r53NS, http.StatusNotFound, "NoSuchHostedZone")
		return
	}
	next := make(map[string]*rrset, len(z.sets))
	for n, set := range z.sets {
		next[n] = set
	}
	before := map[string][]string{}
	for _, c := range req.Changes {
		n := normName(c.Set.Name)
		vals, shaped := flatValues(c.Set.Records)
		if !shaped || c.Set.Type != "TXT" || c.Set.TTL == nil || *c.Set.TTL < 0 || *c.Set.TTL > maxTTL {
			s.mu.Unlock()
			writeError(w, r53NS, http.StatusBadRequest, "InvalidInput") // the fake serves TXT only
			return
		}
		msg := ""
		switch {
		case n != z.name && !strings.HasSuffix(n, "."+z.name):
			msg = "the name is not permitted in the zone"
		case !validValues(vals):
			msg = "invalid resource record"
		case c.Action == "CREATE" && next[n] != nil:
			msg = "the record set already exists"
		case c.Action == "DELETE" && next[n] == nil:
			msg = "the record set to delete was not found"
		case c.Action == "DELETE" && !sameSet(next[n], *c.Set.TTL, vals):
			msg = "the values provided do not match the current values"
		case c.Action != "CREATE" && c.Action != "DELETE" && c.Action != "UPSERT":
			s.mu.Unlock()
			writeError(w, r53NS, http.StatusBadRequest, "InvalidInput")
			return
		}
		if msg != "" {
			s.mu.Unlock()
			writeInvalidChangeBatch(w, msg)
			return
		}
		if _, seen := before[n]; !seen {
			before[n] = nil
			if cur := z.sets[n]; cur != nil {
				before[n] = cur.values
			}
		}
		if c.Action == "DELETE" {
			delete(next, n)
		} else {
			next[n] = &rrset{ttl: *c.Set.TTL, values: vals}
		}
	}
	z.sets = next
	id := "C" + randomUpper(13)
	s.changes[id] = s.o.InsyncAfter
	after := map[string][]string{}
	for n := range before {
		if set := next[n]; set != nil {
			after[n] = set.values
		}
	}
	s.mu.Unlock()
	for n, old := range before {
		s.mirror(n, old, after[n])
	}
	s.count(OpChange)
	writeXML(w, http.StatusOK, changeResponseXML{
		XMLName:    xml.Name{Space: r53NS, Local: "ChangeResourceRecordSetsResponse"},
		ChangeInfo: changeInfoXML{ID: "/change/" + id, Status: "PENDING", SubmittedAt: s.now().UTC().Format("2006-01-02T15:04:05.000Z"), Comment: req.Comment},
	})
}

// getChange is GetChange: PENDING for the change's first InsyncAfter polls, INSYNC afterwards.
func (s *Server) getChange(w http.ResponseWriter, id string) {
	s.mu.Lock()
	left, ok := s.changes[id]
	if ok && left > 0 {
		s.changes[id] = left - 1
	}
	s.mu.Unlock()
	if !ok {
		writeError(w, r53NS, http.StatusNotFound, "NoSuchChange")
		return
	}
	status := "INSYNC"
	if left > 0 {
		status = "PENDING"
	}
	s.count(OpGetChange)
	writeXML(w, http.StatusOK, changeResponseXML{
		XMLName:    xml.Name{Space: r53NS, Local: "GetChangeResponse"},
		ChangeInfo: changeInfoXML{ID: "/change/" + id, Status: status, SubmittedAt: s.now().UTC().Format("2006-01-02T15:04:05.000Z")},
	})
}

func (s *Server) zoneLocked(id string) *zone {
	for _, z := range s.zones {
		if z.id == id {
			return z
		}
	}
	return nil
}

// mirror tells the sink which unquoted values of name went and came.
func (s *Server) mirror(name string, old, now []string) {
	if s.o.Sink == nil {
		return
	}
	had, has := map[string]bool{}, map[string]bool{}
	for _, v := range old {
		had[unquote(v)] = true
	}
	for _, v := range now {
		has[unquote(v)] = true
	}
	for v := range had {
		if !has[v] {
			s.o.Sink.DNSClear(name, v)
		}
	}
	for v := range has {
		if !had[v] {
			s.o.Sink.DNSSet(name, v)
		}
	}
}

func sameSet(cur *rrset, ttl int, values []string) bool {
	if cur.ttl != ttl || len(cur.values) != len(values) {
		return false
	}
	a, b := append([]string(nil), cur.values...), append([]string(nil), values...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validValues(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, v := range values {
		if _, ok := parseQuoted(v); !ok {
			return false
		}
	}
	return true
}

// parseQuoted reads a TXT value in Route 53's form: quoted character strings of at most 255 bytes, separated by
// spaces, with \" \\ and \ooo escapes (Route 53 writes other bytes as a backslash and three octal digits).
func parseQuoted(raw string) ([]string, bool) {
	var out []string
	i := 0
	for {
		for i < len(raw) && raw[i] == ' ' {
			i++
		}
		if i == len(raw) {
			return out, len(out) > 0
		}
		if raw[i] != '"' {
			return nil, false
		}
		i++
		var b []byte
		for {
			if i >= len(raw) {
				return nil, false
			}
			c := raw[i]
			if c == '"' {
				i++
				break
			}
			if c == '\\' {
				if i+3 < len(raw) && isOctal(raw[i+1]) && isOctal(raw[i+2]) && isOctal(raw[i+3]) {
					n, _ := strconv.ParseUint(raw[i+1:i+4], 8, 8)
					b = append(b, byte(n))
					i += 4
					continue
				}
				if i+1 >= len(raw) {
					return nil, false
				}
				b = append(b, raw[i+1])
				i += 2
				continue
			}
			b = append(b, c)
			i++
		}
		if len(b) > 255 {
			return nil, false
		}
		out = append(out, string(b))
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// unquote is the text of a quoted TXT value (its strings joined), or raw when it is not one.
func unquote(raw string) string {
	parts, ok := parseQuoted(raw)
	if !ok {
		return raw
	}
	return strings.Join(parts, "")
}

// quote is the Route 53 form of a TXT text.
func quote(v string) string {
	if v == "" {
		return `""`
	}
	var parts []string
	for len(v) > 0 {
		n := min(255, len(v))
		esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v[:n])
		parts = append(parts, `"`+esc+`"`)
		v = v[n:]
	}
	return strings.Join(parts, " ")
}

func reverseKey(name string) string {
	labels := strings.Split(name, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

func itemsParam(v string, limit int) (int, bool) {
	if v == "" {
		return limit, true
	}
	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 1 && n <= limit
}

func dnsChars(n string) bool {
	for i := 0; i < len(n); i++ {
		c := n[i]
		switch {
		case c >= 'a' && c <= 'z', isDigit(c), c == '-', c == '_', c == '.', c == '*':
		default:
			return false
		}
	}
	return true
}

func validType(t string) bool {
	switch t {
	case "A", "AAAA", "CAA", "CNAME", "DS", "HTTPS", "MX", "NAPTR", "NS", "PTR", "SOA", "SPF", "SRV", "SSHFP", "SVCB", "TLSA", "TXT":
		return true
	}
	return false
}

type errorXML struct {
	XMLName xml.Name
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	RequestID string `xml:"RequestId"`
}

// writeError answers AWS's error document. The message is fixed per code: the fake never copies the request into it.
func writeError(w http.ResponseWriter, ns string, status int, code string) {
	e := errorXML{XMLName: xml.Name{Space: ns, Local: "ErrorResponse"}, RequestID: randomUpper(20)}
	e.Error.Type, e.Error.Code, e.Error.Message = "Sender", code, "fake: "+code
	if status >= 500 {
		e.Error.Type = "Receiver"
	}
	writeXML(w, status, e)
}

type invalidBatchXML struct {
	XMLName   xml.Name `xml:"https://route53.amazonaws.com/doc/2013-04-01/ InvalidChangeBatch"`
	Messages  []string `xml:"Messages>Message"`
	RequestID string   `xml:"RequestId"`
}

// writeInvalidChangeBatch answers Route 53's refusal of a change batch (HTTP 400, its own root element).
func writeInvalidChangeBatch(w http.ResponseWriter, msg string) {
	writeXML(w, http.StatusBadRequest, invalidBatchXML{Messages: []string{"fake: " + msg}, RequestID: randomUpper(20)})
}

func writeXML(w http.ResponseWriter, status int, v any) {
	out, err := xml.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	body := append([]byte(xml.Header), out...)
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
