package fakecloudflare

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const prefix = "/client/v4"

type apiError struct {
	Code       int        `json:"code"`
	Message    string     `json:"message"`
	ErrorChain []apiError `json:"error_chain,omitempty"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

type envelope struct {
	Result     any         `json:"result"`
	Success    bool        `json:"success"`
	Errors     []apiError  `json:"errors"`
	Messages   []apiError  `json:"messages"`
	ResultInfo *resultInfo `json:"result_info,omitempty"`
}

type zoneJSON struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Status              string   `json:"status"`
	Paused              bool     `json:"paused"`
	Type                string   `json:"type"`
	DevelopmentMode     int      `json:"development_mode"`
	NameServers         []string `json:"name_servers"`
	OriginalNameServers []string `json:"original_name_servers"`
}

type recordJSON struct {
	ID         string         `json:"id"`
	ZoneID     string         `json:"zone_id"`
	ZoneName   string         `json:"zone_name"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Content    string         `json:"content"`
	Proxiable  bool           `json:"proxiable"`
	Proxied    bool           `json:"proxied"`
	TTL        int            `json:"ttl"`
	Locked     bool           `json:"locked"`
	Meta       map[string]any `json:"meta"`
	Comment    *string        `json:"comment"`
	Tags       []string       `json:"tags"`
	CreatedOn  string         `json:"created_on"`
	ModifiedOn string         `json:"modified_on"`
}

func writeJSON(w http.ResponseWriter, status int, e envelope) {
	if e.Errors == nil {
		e.Errors = []apiError{}
	}
	if e.Messages == nil {
		e.Messages = []apiError{}
	}
	e.Success = status >= 200 && status < 300 && len(e.Errors) == 0
	b, _ := json.Marshal(e)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeError(w http.ResponseWriter, status, code int, msg string) {
	writeJSON(w, status, envelope{Errors: []apiError{{Code: code, Message: msg}}})
}

// route names the op of a request and splits its path: /zones, /zones/{id}/dns_records and
// /zones/{id}/dns_records/{rid}. A known path with another method is op "" with methodOK false.
func route(r *http.Request) (op, zoneID, recordID string, known, methodOK bool) {
	p, ok := strings.CutPrefix(r.URL.Path, prefix+"/zones")
	if !ok {
		return "", "", "", false, false
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case p == "" || p == "/":
		return OpZones, "", "", true, r.Method == http.MethodGet
	case len(parts) == 2 && parts[1] == "dns_records":
		switch r.Method {
		case http.MethodGet:
			return OpList, parts[0], "", true, true
		case http.MethodPost:
			return OpCreate, parts[0], "", true, true
		}
		return "", parts[0], "", true, false
	case len(parts) == 3 && parts[1] == "dns_records":
		return OpDelete, parts[0], parts[2], true, r.Method == http.MethodDelete
	}
	return "", "", "", false, false
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	op, zid, rid, known, methodOK := route(r)
	if !methodOK {
		op = ""
	}
	sw := &statusWriter{ResponseWriter: w}
	i := s.record(r, op)
	defer func() { s.setStatus(i, sw.status) }()
	if f := s.takeFault(op); f != nil && s.applyFault(sw, r, f) {
		return
	}
	switch {
	case !known:
		writeError(sw, http.StatusNotFound, 7000, "No route for that URI")
		return
	case !methodOK:
		writeError(sw, http.StatusMethodNotAllowed, 7001, "Method not allowed for this endpoint")
		return
	}
	if !s.authorized(sw, r) {
		return
	}
	switch op {
	case OpZones:
		s.listZones(sw, r)
	case OpCreate:
		s.createRecord(sw, r, zid)
	case OpList:
		s.listRecords(sw, r, zid)
	default:
		s.deleteRecord(sw, zid, rid)
	}
}

// paging reads page and per_page (Cloudflare's bounds: per_page lo..hi, default def).
func paging(r *http.Request, def, lo, hi int) (page, per int, ok bool) {
	page, per = 1, def
	q := r.URL.Query()
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return 0, 0, false
		}
		page = n
	}
	if v := q.Get("per_page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			return 0, 0, false
		}
		per = n
	}
	return page, per, true
}

func pageOf[T any](all []T, page, per int) ([]T, *resultInfo) {
	total := len(all)
	pages := (total + per - 1) / per
	from := min((page-1)*per, total)
	to := min(from+per, total)
	out := append([]T{}, all[from:to]...)
	return out, &resultInfo{Page: page, PerPage: per, Count: len(out), TotalCount: total, TotalPages: pages}
}

func (s *Server) listZones(w http.ResponseWriter, r *http.Request) {
	page, per, ok := paging(r, 20, 5, 50)
	if !ok {
		writeError(w, http.StatusBadRequest, 1001, "Invalid paging parameters")
		return
	}
	q := r.URL.Query()
	name, status := normName(q.Get("name")), q.Get("status")
	var all []zoneJSON
	s.mu.Lock()
	for _, z := range s.zones {
		if !z.allowed || (name != "" && z.name != name) || (status != "" && status != "active") {
			continue
		}
		all = append(all, zoneJSON{ID: z.id, Name: z.name, Status: "active", Type: "full",
			NameServers: []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}, OriginalNameServers: []string{}})
	}
	s.mu.Unlock()
	res, info := pageOf(all, page, per)
	writeJSON(w, http.StatusOK, envelope{Result: res, ResultInfo: info})
}

// zoneFor finds a zone the token may use: 404 7003 for an unknown ID (Cloudflare's "Could not route"), 403 10000
// for a zone outside the token's zones (GUESS: the code of a token without permission on the zone).
func (s *Server) zoneFor(w http.ResponseWriter, id string) *zone {
	z := s.zoneByID(id)
	if z == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, 7003, "Could not route to /zones, perhaps your object identifier is invalid?")
		return nil
	}
	if !z.allowed {
		s.mu.Unlock()
		writeError(w, http.StatusForbidden, 10000, "Authentication error")
		return nil
	}
	return z
}

func (s *Server) createRecord(w http.ResponseWriter, r *http.Request, zid string) {
	var in struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, 9207, "Request body is invalid.")
		return
	}
	s.mu.Lock()
	z := s.zoneFor(w, zid)
	if z == nil {
		return
	}
	name := normName(in.Name)
	switch {
	case in.Type != "TXT":
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, 1004, "DNS Validation Error") // the fake creates TXT records only
		return
	case name != z.name && !strings.HasSuffix(name, "."+z.name):
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, 9005, "Content for TXT record is invalid. The record name must be in the zone.")
		return
	case in.Content == "" || len(in.Content) > 2048:
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, 9009, "Content for TXT record is invalid.")
		return
	case in.TTL != 1 && (in.TTL < 60 || in.TTL > 86400):
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, 9021, "Invalid TTL. Must be between 60 and 86400, or 1 for automatic.")
		return
	}
	for _, x := range s.records {
		// GUESS: Cloudflare compares the stored content; the fake compares it unquoted.
		if x.ZoneID == z.id && x.Type == in.Type && x.Name == name && Unquote(x.Content) == Unquote(in.Content) {
			s.mu.Unlock()
			writeError(w, http.StatusBadRequest, 81058, "An identical record already exists.")
			return
		}
	}
	rec := Record{ID: NewID(), ZoneID: z.id, ZoneName: z.name, Type: in.Type, Name: name, Content: in.Content, TTL: in.TTL}
	s.records = append(s.records, rec)
	now := s.now().UTC().Format(time.RFC3339Nano)
	s.mu.Unlock()
	s.mirror(rec, true)
	var msgs []apiError
	if Unquote(in.Content) == in.Content {
		msgs = []apiError{{Code: 100, Message: "Content for TXT record should be in quotes."}}
	}
	writeJSON(w, http.StatusOK, envelope{Result: recordOut(rec, now), Messages: msgs})
}

func recordOut(r Record, now string) recordJSON {
	return recordJSON{ID: r.ID, ZoneID: r.ZoneID, ZoneName: r.ZoneName, Name: r.Name, Type: r.Type, Content: r.Content,
		TTL: r.TTL, Meta: map[string]any{"auto_added": false}, Tags: []string{}, CreatedOn: now, ModifiedOn: now}
}

func (s *Server) listRecords(w http.ResponseWriter, r *http.Request, zid string) {
	page, per, ok := paging(r, 100, 5, 5000)
	if !ok {
		writeError(w, http.StatusBadRequest, 1001, "Invalid paging parameters")
		return
	}
	q := r.URL.Query()
	typ, name, content := q.Get("type"), normName(q.Get("name")), q.Get("content")
	s.mu.Lock()
	z := s.zoneFor(w, zid)
	if z == nil {
		return
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	var all []recordJSON
	for _, x := range s.records {
		if x.ZoneID != z.id || (typ != "" && x.Type != typ) || (name != "" && x.Name != name) || (content != "" && x.Content != content) {
			continue
		}
		all = append(all, recordOut(x, now))
	}
	s.mu.Unlock()
	res, info := pageOf(all, page, per)
	writeJSON(w, http.StatusOK, envelope{Result: res, ResultInfo: info})
}

func (s *Server) deleteRecord(w http.ResponseWriter, zid, rid string) {
	s.mu.Lock()
	z := s.zoneFor(w, zid)
	if z == nil {
		return
	}
	for i, x := range s.records {
		if x.ZoneID == z.id && x.ID == rid {
			s.records = append(s.records[:i], s.records[i+1:]...)
			s.mu.Unlock()
			s.mirror(x, false)
			writeJSON(w, http.StatusOK, envelope{Result: map[string]string{"id": x.ID}})
			return
		}
	}
	s.mu.Unlock()
	writeError(w, http.StatusNotFound, 81044, "Record does not exist.")
}
