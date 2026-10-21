package fakekv

// The Azure DNS side of the fake: the Azure Resource Manager host (https://management.azure.com) serving the
// public DNS zones of one subscription and resource group, and their TXT record sets, at api-version 2018-05-01
// (Microsoft.Network/dnsZones, https://learn.microsoft.com/en-us/rest/api/dns/). It shares the Entra ID token
// endpoint, the IMDS endpoint, the request log and the fault mechanism with the Key Vault side; tokens must carry
// the audience https://management.azure.com.
//
// Fault keys (FailNext/FailAll path prefixes; the prefix matches every route below it):
//
//	"/subscriptions/"   every ARM request
//	DNSZonesPath()      the zone listing AND every record set below it (the listing is the first request a
//	                    provider sends for a name, so FailNext on it hits the listing)
//	DNSRecordPath(z, n) one record set; its GET is the first request of an add or a removal, so a fault meant
//	                    for the following PUT or DELETE is queued behind a pass-through Fault{} (status 0, no body:
//	                    the real answer)
//
// A fault without a body answers the ARM error shape {"error":{"code","message"}} (defaultFaultBody).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
)

const (
	// DNSAPIVersion is the only Azure DNS api-version the fake serves.
	DNSAPIVersion = "2018-05-01"
	// managementHost is the Azure Resource Manager host.
	managementHost = "management.azure.com"
	// managementResource is the audience of every Resource Manager access token.
	managementResource = "https://management.azure.com"
)

// DNSSink mirrors the TXT values the fake's record sets hold (a *fakeacme.Server satisfies it: its DNS-01
// validation then sees what the provider published).
type DNSSink interface {
	DNSSet(fqdn, value string)
	DNSClear(fqdn, value string)
}

type dnsRecordSet struct {
	ttl      int
	records  [][]string // each TXT record is a list of strings; its value is their concatenation
	etag     string
	metadata map[string]string
}

type dnsState struct {
	mu        sync.Mutex
	sub, rg   string
	zones     []string        // public zones, lower case, in the listing's order
	private   map[string]bool // zone names (lower case) of the listing's "Private" zones
	pageSize  int
	sink      DNSSink
	readOnly  bool
	recordSet map[string]*dnsRecordSet // zone + "/" + relative name (lower case)
}

func newDNSState(o Options) *dnsState {
	d := &dnsState{sub: foldASCII(o.DNSSubscriptionID), rg: o.DNSResourceGroup, private: map[string]bool{},
		pageSize: o.DNSPageSize, sink: o.DNSSink, readOnly: o.DNSReadOnly, recordSet: map[string]*dnsRecordSet{}}
	if d.sub == "" {
		d.sub = uuid.NewString()
	}
	if d.rg == "" {
		d.rg = "alice-dns"
	}
	for _, z := range o.DNSZones {
		d.zones = append(d.zones, foldASCII(strings.TrimSuffix(z, ".")))
	}
	for _, z := range o.DNSPrivateZones {
		n := foldASCII(strings.TrimSuffix(z, "."))
		d.zones = append(d.zones, n)
		d.private[n] = true
	}
	return d
}

// DNSSubscriptionID is the subscription that holds the fake's DNS zones.
func (s *Server) DNSSubscriptionID() string { return s.dns.sub }

// DNSResourceGroup is the resource group that holds the fake's DNS zones.
func (s *Server) DNSResourceGroup() string { return s.dns.rg }

// DNSZonesPath is the path of the zone listing (a fault key).
func (s *Server) DNSZonesPath() string {
	return "/subscriptions/" + s.dns.sub + "/resourceGroups/" + s.dns.rg + "/providers/Microsoft.Network/dnsZones"
}

// DNSRecordPath is the path of the TXT record set relative ("@" for the apex) in zone (a fault key).
func (s *Server) DNSRecordPath(zone, relative string) string {
	return s.DNSZonesPath() + "/" + foldASCII(zone) + "/TXT/" + foldASCII(relative)
}

// SetDNSReadOnly makes every PUT and DELETE of a record set answer 403 AuthorizationFailed (the identity has
// Reader but not "DNS Zone Contributor"); false restores writes.
func (s *Server) SetDNSReadOnly(on bool) { s.dns.mu.Lock(); s.dns.readOnly = on; s.dns.mu.Unlock() }

// SetDNSTXT replaces the TXT record set relative ("@" for the apex) of zone with one record per value (another
// system's records, for tests that prove a provider keeps them). No values deletes it. The sink is not told.
func (s *Server) SetDNSTXT(zone, relative string, ttl int, values ...string) {
	key := foldASCII(zone) + "/" + foldASCII(relative)
	s.dns.mu.Lock()
	defer s.dns.mu.Unlock()
	if len(values) == 0 {
		delete(s.dns.recordSet, key)
		return
	}
	rs := &dnsRecordSet{ttl: ttl, etag: uuid.NewString(), metadata: map[string]string{"owner": "someone-else"}}
	for _, v := range values {
		rs.records = append(rs.records, []string{v})
	}
	s.dns.recordSet[key] = rs
}

// DNSRecords is a copy of the TXT values of every record set, by fully qualified name (no trailing dot).
func (s *Server) DNSRecords() map[string][]string {
	s.dns.mu.Lock()
	defer s.dns.mu.Unlock()
	out := make(map[string][]string, len(s.dns.recordSet))
	for key, rs := range s.dns.recordSet {
		zone, rel, _ := strings.Cut(key, "/")
		out[fqdnOf(zone, rel)] = rs.values()
	}
	return out
}

// DNSRecordTTL is the TTL of the TXT record set at fqdn (0 when there is none).
func (s *Server) DNSRecordTTL(fqdn string) int {
	s.dns.mu.Lock()
	defer s.dns.mu.Unlock()
	for key, rs := range s.dns.recordSet {
		zone, rel, _ := strings.Cut(key, "/")
		if fqdnOf(zone, rel) == foldASCII(fqdn) {
			return rs.ttl
		}
	}
	return 0
}

// DNSRecordMetadata is the metadata of the TXT record set at fqdn (nil when there is none).
func (s *Server) DNSRecordMetadata(fqdn string) map[string]string {
	s.dns.mu.Lock()
	defer s.dns.mu.Unlock()
	for key, rs := range s.dns.recordSet {
		zone, rel, _ := strings.Cut(key, "/")
		if fqdnOf(zone, rel) == foldASCII(fqdn) {
			out := make(map[string]string, len(rs.metadata))
			for k, v := range rs.metadata {
				out[k] = v
			}
			return out
		}
	}
	return nil
}

func fqdnOf(zone, rel string) string {
	if rel == "@" {
		return zone
	}
	return rel + "." + zone
}

func (rs *dnsRecordSet) values() []string {
	out := make([]string, 0, len(rs.records))
	for _, r := range rs.records {
		out = append(out, strings.Join(r, ""))
	}
	return out
}

// serveManagement is the pipeline of a Resource Manager request: the token first (an unauthenticated request
// never consumes a fault), then latency, hold and scripted faults, then the route.
func (s *Server) serveManagement(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		// ARM's answer to a request without a token (shape documented; text observed, GUESS).
		w.Header().Set("WWW-Authenticate", `Bearer authorization_uri="https://login.windows.net/", error="invalid_token", error_description="The authentication failed because of missing 'Authorization' header."`)
		armFail(w, http.StatusUnauthorized, "AuthenticationFailed", "Authentication failed. The 'Authorization' header is missing.")
		return
	}
	s.mu.Lock()
	t, known := s.tokens[tok]
	s.mu.Unlock()
	now := s.o.Now()
	switch {
	case !known:
		armFail(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "The access token is invalid.")
		return
	case !now.Before(t.exp) || now.Add(tokenSkew).Before(t.nbf):
		armFail(w, http.StatusUnauthorized, "ExpiredAuthenticationToken", "The access token expiry UTC time is earlier than current UTC time.")
		return
	case t.aud != managementResource:
		armFail(w, http.StatusUnauthorized, "InvalidAuthenticationTokenAudience", "The access token has been obtained for wrong audience or resource.") // GUESS text
		return
	}
	s.serveWithFaults(w, r, s.dnsRoute)
}

// armFail writes the Resource Manager error shape.
func armFail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func (s *Server) dnsRoute(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("api-version") != DNSAPIVersion {
		// GUESS: ARM's code for an api-version the resource provider does not serve.
		armFail(w, http.StatusBadRequest, "NoRegisteredProviderFound", "No registered resource provider found for the API version '"+r.URL.Query().Get("api-version")+"'.")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i := range parts {
		parts[i] = foldASCII(parts[i]) // ARM paths are case-insensitive
	}
	n := len(parts)
	if n < 7 || parts[0] != "subscriptions" || parts[2] != "resourcegroups" || parts[4] != "providers" ||
		parts[5] != "microsoft.network" || parts[6] != "dnszones" {
		armFail(w, http.StatusNotFound, "InvalidResourceType", "The resource type could not be found in the namespace.") // GUESS
		return
	}
	d := s.dns
	switch {
	case parts[1] != d.sub:
		armFail(w, http.StatusNotFound, "SubscriptionNotFound", "The subscription '"+parts[1]+"' could not be found.")
		return
	case parts[3] != foldASCII(d.rg):
		armFail(w, http.StatusNotFound, "ResourceGroupNotFound", "Resource group '"+parts[3]+"' could not be found.")
		return
	}
	switch {
	case n == 7 && r.Method == http.MethodGet:
		s.listDNSZones(w, r)
	case n == 10 && parts[8] == "txt":
		s.txtRecordSet(w, r, parts[7], parts[9])
	case n == 7 || (n == 10 && parts[8] == "txt"):
		w.WriteHeader(http.StatusMethodNotAllowed)
	default:
		armFail(w, http.StatusNotFound, "NotFound", "The fake serves the zone listing and TXT record sets only.") // GUESS
	}
}

func (s *Server) zoneJSON(zone string, private bool, recordSets int) map[string]any {
	kind := "Public"
	if private {
		kind = "Private"
	}
	return map[string]any{
		"id":       s.armZoneID(zone),
		"name":     zone,
		"type":     "Microsoft.Network/dnszones",
		"etag":     "00000000-0000-0000-0000-000000000000",
		"location": "global",
		"tags":     map[string]any{},
		"properties": map[string]any{
			"maxNumberOfRecordSets": 10000, "maxNumberOfRecordsPerRecordSet": nil, "numberOfRecordSets": recordSets,
			"nameServers": []string{"ns1-01.azure-dns.com.", "ns2-01.azure-dns.net.", "ns3-01.azure-dns.org.", "ns4-01.azure-dns.info."},
			"zoneType":    kind,
		},
	}
}

func (s *Server) armZoneID(zone string) string {
	return "/subscriptions/" + s.dns.sub + "/resourceGroups/" + s.dns.rg + "/providers/Microsoft.Network/dnszones/" + zone
}

// listDNSZones answers the zone listing, paged by Options.DNSPageSize with a $skipToken (the token's form is
// a GUESS: Azure's is opaque).
func (s *Server) listDNSZones(w http.ResponseWriter, r *http.Request) {
	d := s.dns
	d.mu.Lock()
	type zoneRow struct {
		name    string
		private bool
		sets    int
	}
	rows := make([]zoneRow, 0, len(d.zones))
	for _, z := range d.zones {
		sets := 2 // SOA and NS
		for key := range d.recordSet {
			if strings.HasPrefix(key, z+"/") {
				sets++
			}
		}
		rows = append(rows, zoneRow{z, d.private[z], sets})
	}
	size := d.pageSize
	d.mu.Unlock()
	start := 0
	if tok := r.URL.Query().Get("$skipToken"); tok != "" {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 0 || n > len(rows) {
			armFail(w, http.StatusBadRequest, "InvalidSkipToken", "The skip token is not valid.") // GUESS
			return
		}
		start = n
	}
	end := len(rows)
	if size > 0 && start+size < end {
		end = start + size
	}
	value := make([]any, 0, end-start)
	for _, z := range rows[start:end] {
		value = append(value, s.zoneJSON(z.name, z.private, z.sets))
	}
	body := map[string]any{"value": value}
	if end < len(rows) {
		q := url.Values{"api-version": {DNSAPIVersion}, "$skipToken": {strconv.Itoa(end)}}
		body["nextLink"] = "https://" + managementHost + r.URL.Path + "?" + q.Encode()
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) recordSetJSON(zone, rel string, rs *dnsRecordSet) map[string]any {
	recs := make([]any, 0, len(rs.records))
	for _, r := range rs.records {
		recs = append(recs, map[string]any{"value": r})
	}
	md := map[string]any{}
	for k, v := range rs.metadata {
		md[k] = v
	}
	return map[string]any{
		"id":   s.armZoneID(zone) + "/TXT/" + rel,
		"name": rel,
		"type": "Microsoft.Network/dnszones/TXT",
		"etag": rs.etag,
		"properties": map[string]any{
			"metadata": md, "TTL": rs.ttl, "fqdn": fqdnOf(zone, rel) + ".", "provisioningState": "Succeeded",
			"targetResource": map[string]any{}, "TXTRecords": recs,
		},
	}
}

func (s *Server) knownZone(zone string) bool {
	for _, z := range s.dns.zones {
		if z == zone {
			return true
		}
	}
	return false
}

// txtRecordSet serves GET, PUT and DELETE of one TXT record set with the documented ETag rules: If-Match must
// name the current etag, If-None-Match: * requires that there is none; a mismatch is 412 PreconditionFailed.
func (s *Server) txtRecordSet(w http.ResponseWriter, r *http.Request, zone, rel string) {
	d := s.dns
	key := zone + "/" + rel
	ifMatch, ifNone := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
	var set, clear []string // sink changes, made after the lock
	defer func() {
		if d.sink == nil {
			return
		}
		fqdn := fqdnOf(zone, rel)
		for _, v := range set {
			d.sink.DNSSet(fqdn, v)
		}
		for _, v := range clear {
			d.sink.DNSClear(fqdn, v)
		}
	}()
	oid := s.ObjectID()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !s.knownZone(zone) || d.private[zone] {
		armFail(w, http.StatusNotFound, "ParentResourceNotFound", "Can not perform requested operation on nested resource. Parent resource '"+zone+"' not found.")
		return
	}
	cur := d.recordSet[key]
	if r.Method != http.MethodGet && d.readOnly {
		armFail(w, http.StatusForbidden, "AuthorizationFailed", "The client '"+oid+"' with object id '"+oid+
			"' does not have authorization to perform action 'Microsoft.Network/dnszones/TXT/write' over scope '"+
			s.armZoneID(zone)+"/TXT/"+rel+"' or the scope is invalid. If access was recently granted, please refresh your credentials.")
		return
	}
	precondition := func() bool {
		switch {
		case ifMatch != "" && (cur == nil || (ifMatch != "*" && ifMatch != cur.etag)):
		case ifNone == "*" && cur != nil:
		default:
			return true
		}
		armFail(w, http.StatusPreconditionFailed, "PreconditionFailed", "The condition specified using HTTP conditional header(s) is not met.")
		return false
	}
	switch r.Method {
	case http.MethodGet:
		if cur == nil {
			armFail(w, http.StatusNotFound, "NotFound", "The resource record '"+rel+"' does not exist in resource group '"+d.rg+"' of subscription '"+d.sub+"'.")
			return
		}
		w.Header().Set("ETag", cur.etag)
		writeJSON(w, http.StatusOK, s.recordSetJSON(zone, rel, cur))
	case http.MethodPut:
		if !precondition() {
			return
		}
		next, ok := parseTXTBody(r)
		if !ok {
			armFail(w, http.StatusBadRequest, "BadRequest", "The request body is not a valid TXT record set.") // GUESS
			return
		}
		next.etag = uuid.NewString()
		status := http.StatusOK
		var old []string
		if cur == nil {
			status = http.StatusCreated
		} else {
			old = cur.values()
		}
		set, clear = diffValues(old, next.values())
		d.recordSet[key] = next
		w.Header().Set("ETag", next.etag)
		writeJSON(w, status, s.recordSetJSON(zone, rel, next))
	case http.MethodDelete:
		if !precondition() {
			return
		}
		if cur == nil {
			w.WriteHeader(http.StatusNoContent) // deleting what is not there succeeds
			return
		}
		clear = cur.values()
		delete(d.recordSet, key)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// parseTXTBody reads {"properties":{"TTL":n,"TXTRecords":[{"value":[...]}],"metadata":{...}}}: TTL 1..2147483647,
// at least one record, every record 1..10 strings of at most 1024 characters (GUESS: Azure's documented limits).
func parseTXTBody(r *http.Request) (*dnsRecordSet, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, false
	}
	var body struct {
		Properties *struct {
			TTL        *int              `json:"TTL"`
			Metadata   map[string]string `json:"metadata"`
			TXTRecords []struct {
				Value []string `json:"value"`
			} `json:"TXTRecords"`
		} `json:"properties"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Properties == nil || body.Properties.TTL == nil || *body.Properties.TTL < 1 ||
		len(body.Properties.TXTRecords) == 0 {
		return nil, false
	}
	rs := &dnsRecordSet{ttl: *body.Properties.TTL, metadata: body.Properties.Metadata}
	for _, rec := range body.Properties.TXTRecords {
		if len(rec.Value) == 0 || len(rec.Value) > 10 {
			return nil, false
		}
		for _, v := range rec.Value {
			if len(v) > 1024 {
				return nil, false
			}
		}
		rs.records = append(rs.records, append([]string(nil), rec.Value...))
	}
	return rs, true
}

// diffValues lists the values of next not in old (added) and of old not in next (removed), sorted.
func diffValues(old, next []string) (added, removed []string) {
	in := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	for _, v := range next {
		if !in(old, v) && !in(added, v) {
			added = append(added, v)
		}
	}
	for _, v := range old {
		if !in(next, v) && !in(removed, v) {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
