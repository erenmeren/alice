package web

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"alice/internal/vconsole/store"
	"alice/internal/vconsole/webuser"
)

const (
	maxFormBody = 64 << 10
	homeDays    = 90
	// licenseExt is the extension of license files everywhere in the product (docs/vendor).
	licenseExt = ".alicelic"
)

// licenseIDPattern is what a license ID may look like on the wire; anything else is 404 before the
// database is asked, so odd input never reaches a query, a header or a file name.
var licenseIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// pages registers the signed-in pages: home, customers, requests, licenses and downloads. Every
// handler goes through authed; the cross-origin check for POSTs wraps the whole mux.
func (s *Server) pages(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.authed(s.home))
	mux.HandleFunc("GET /customers", s.authed(s.customersPage))
	mux.HandleFunc("POST /customers", s.authed(s.customerAdd))
	mux.HandleFunc("GET /requests/new", s.authed(s.requestNewPage))
	mux.HandleFunc("POST /requests", s.authed(s.requestAdd))
	mux.HandleFunc("GET /requests/{id}", s.authed(s.requestPage))
	mux.HandleFunc("POST /requests/{id}/cancel", s.authed(s.requestCancel))
	mux.HandleFunc("GET /licenses", s.authed(s.licensesPage))
	mux.HandleFunc("GET /licenses/{id}/download", s.authed(s.licenseDownload))
}

// serverError answers 500 with a generic page; the cause goes to the log only (never a request body
// or URL).
func (s *Server) serverError(w http.ResponseWriter, what string, err error) {
	s.log.Error("web: "+what, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// readForm caps the body and parses it. It answers the error itself and reports whether to go on.
func (s *Server) readForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		return false
	}
	return true
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

type homeData struct {
	Requests []store.Request
	Licenses []store.LicenseRow
	Days     int
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, u webuser.User) {
	d := homeData{Days: homeDays}
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		if d.Requests, err = store.ListRequests(r.Context(), tx, "open"); err != nil {
			return err
		}
		d.Licenses, err = store.ListLicenses(r.Context(), tx, s.cfg.Clock.Now(), homeDays, false)
		return err
	})
	if err != nil {
		s.serverError(w, "home", err)
		return
	}
	s.render(w, http.StatusOK, "home", pageData{User: u, Data: d})
}

type customerForm struct{ Name, Contact, Notes string }

type customersData struct {
	Customers []store.Customer
	Form      customerForm
	Error     string
}

func (s *Server) renderCustomers(w http.ResponseWriter, r *http.Request, u webuser.User, status int, form customerForm, msg string) {
	d := customersData{Form: form, Error: msg}
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		d.Customers, err = store.ListCustomers(r.Context(), tx)
		return err
	})
	if err != nil {
		s.serverError(w, "list customers", err)
		return
	}
	s.render(w, status, "customers", pageData{User: u, Data: d})
}

func (s *Server) customersPage(w http.ResponseWriter, r *http.Request, u webuser.User) {
	s.renderCustomers(w, r, u, http.StatusOK, customerForm{}, "")
}

func (s *Server) customerAdd(w http.ResponseWriter, r *http.Request, u webuser.User) {
	if !s.readForm(w, r) {
		return
	}
	f := customerForm{Name: r.PostFormValue("name"), Contact: r.PostFormValue("contact"), Notes: r.PostFormValue("notes")}
	name := strings.TrimSpace(f.Name)
	switch {
	case name == "" || utf8.RuneCountInString(name) > 200:
		s.renderCustomers(w, r, u, http.StatusUnprocessableEntity, f, "The name must be 1 to 200 characters.")
		return
	case utf8.RuneCountInString(strings.TrimSpace(f.Contact)) > 500:
		s.renderCustomers(w, r, u, http.StatusUnprocessableEntity, f, "The contact must be at most 500 characters.")
		return
	case utf8.RuneCountInString(strings.TrimSpace(f.Notes)) > 4000:
		s.renderCustomers(w, r, u, http.StatusUnprocessableEntity, f, "The notes must be at most 4000 characters.")
		return
	}
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) error {
		_, err := store.AddCustomer(r.Context(), tx, store.NewCustomer{Name: f.Name, Contact: f.Contact, Notes: f.Notes})
		return err
	})
	if errors.Is(err, store.ErrDuplicateCustomer) {
		s.renderCustomers(w, r, u, http.StatusUnprocessableEntity, f, "A customer with this name already exists.")
		return
	}
	if err != nil {
		s.serverError(w, "add customer", err)
		return
	}
	http.Redirect(w, r, "/customers", http.StatusSeeOther)
}

type requestForm struct {
	CustomerID, Installation, Targets, From, Months, Features, Replaces string
}

type requestNewData struct {
	Customers []store.Customer
	Form      requestForm
	Error     string
	Renewing  string // the license being renewed, for the banner
}

func (s *Server) renderRequestForm(w http.ResponseWriter, r *http.Request, u webuser.User, status int, f requestForm, msg string) {
	s.renderRequestFormData(w, r, u, status, requestNewData{Form: f, Error: msg})
}

func (s *Server) renderRequestFormData(w http.ResponseWriter, r *http.Request, u webuser.User, status int, d requestNewData) {
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		d.Customers, err = store.ListCustomers(r.Context(), tx)
		return err
	})
	if err != nil {
		s.serverError(w, "list customers", err)
		return
	}
	s.render(w, status, "request_new", pageData{User: u, Data: d})
}

func (s *Server) requestNewPage(w http.ResponseWriter, r *http.Request, u webuser.User) {
	q := r.URL.Query()
	if q.Has("renew") {
		s.renewPage(w, r, u, q.Get("renew"))
		return
	}
	s.renderRequestForm(w, r, u, http.StatusOK, requestForm{CustomerID: q.Get("customer"), Months: "12"}, "")
}

// renewMonths is the term a renewal form starts with (ruling 5); the person can change it.
const renewMonths = "12"

// renewPage is /requests/new?renew=<license-id> (ruling 5): the form prefilled from an old license
// for the person to review and submit. Nothing is stored until they do, and the submit goes through
// the same validation as any request. An odd, unknown or revoked ID is 404, so no data of one
// license can end up in a form opened for another.
func (s *Server) renewPage(w http.ResponseWriter, r *http.Request, u webuser.User, id string) {
	if !licenseIDPattern.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	var old store.Renewal
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		old, err = store.GetLicenseForRenewal(r.Context(), tx, id)
		return err
	})
	if errors.Is(err, store.ErrNotFound) || (err == nil && old.RevokedAt != nil) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, "read license for renewal", err)
		return
	}
	s.renderRequestFormData(w, r, u, http.StatusOK, requestNewData{Renewing: old.LicenseID, Form: requestForm{
		CustomerID:   strconv.FormatInt(old.CustomerID, 10),
		Installation: old.Installation,
		Targets:      strconv.Itoa(old.Targets),
		// The new license starts on the day the old one ends (UTC, like every date the console shows).
		From:     old.ValidUntil.UTC().Format("2006-01-02"),
		Months:   renewMonths,
		Features: strings.Join(old.Features, ","),
	}})
}

// splitFeatures accepts commas or line breaks between features.
func splitFeatures(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
}

func (s *Server) requestAdd(w http.ResponseWriter, r *http.Request, u webuser.User) {
	if !s.readForm(w, r) {
		return
	}
	f := requestForm{
		CustomerID: r.PostFormValue("customer_id"), Installation: r.PostFormValue("installation"),
		Targets: r.PostFormValue("targets"), From: r.PostFormValue("from"), Months: r.PostFormValue("months"),
		Features: r.PostFormValue("features"), Replaces: r.PostFormValue("replaces"),
	}
	refuse := func(msg string) { s.renderRequestForm(w, r, u, http.StatusUnprocessableEntity, f, msg) }
	cid, err := strconv.ParseInt(strings.TrimSpace(f.CustomerID), 10, 64)
	if err != nil || cid <= 0 {
		refuse("Choose a customer.")
		return
	}
	targets, err := strconv.Atoi(strings.TrimSpace(f.Targets))
	if err != nil {
		refuse("Targets must be a whole number.")
		return
	}
	months := 0
	if m := strings.TrimSpace(f.Months); m != "" {
		if months, err = strconv.Atoi(m); err != nil {
			refuse("Months must be a whole number.")
			return
		}
	}
	nr := store.NewRequest{
		CustomerID: cid, Installation: f.Installation, Targets: targets, From: f.From, Months: months,
		Features: splitFeatures(f.Features), Replaces: f.Replaces,
	}
	var id int64
	err = s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		id, err = store.AddRequest(r.Context(), tx, nr, s.cfg.Clock.Now())
		return err
	})
	var invalid *store.InvalidError
	switch {
	case errors.As(err, &invalid):
		refuse(invalid.Err.Error())
		return
	case errors.Is(err, store.ErrNotFound):
		refuse("That customer does not exist.")
		return
	case err != nil:
		s.serverError(w, "add request", err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", id), http.StatusSeeOther)
}

type requestData struct {
	Request store.Request
	// CanCancel is a hint for the button only; the database decides (row-level security).
	CanCancel bool
}

func (s *Server) requestPage(w http.ResponseWriter, r *http.Request, u webuser.User) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	var req store.Request
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		req, err = store.GetRequest(r.Context(), tx, id)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, "get request", err)
		return
	}
	s.render(w, http.StatusOK, "request", pageData{User: u, Data: requestData{
		Request: req, CanCancel: req.Status == "open" && req.RequestedBy == "web:"+u.Name,
	}})
}

func (s *Server) requestCancel(w http.ResponseWriter, r *http.Request, u webuser.User) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) error { return store.CancelRequest(r.Context(), tx, id) })
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, "cancel request", err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", id), http.StatusSeeOther)
}

type licensesData struct {
	Licenses []store.LicenseRow
	Ending   string // "30", "60", "90" or "all"
}

func (s *Server) licensesPage(w http.ResponseWriter, r *http.Request, u webuser.User) {
	ending, days := "all", 0
	switch v := r.URL.Query().Get("ending"); v {
	case "30", "60", "90":
		ending = v
		days, _ = strconv.Atoi(v)
	}
	var rows []store.LicenseRow
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		rows, err = store.ListLicenses(r.Context(), tx, s.cfg.Clock.Now(), days, false)
		return err
	})
	if err != nil {
		s.serverError(w, "list licenses", err)
		return
	}
	s.render(w, http.StatusOK, "licenses", pageData{User: u, Data: licensesData{Licenses: rows, Ending: ending}})
}

func (s *Server) licenseDownload(w http.ResponseWriter, r *http.Request, u webuser.User) {
	id := r.PathValue("id")
	if !licenseIDPattern.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	var raw []byte
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		raw, err = store.LicenseFile(r.Context(), tx, id)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, "download license", err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+id+licenseExt+`"`)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(raw)))
	_, _ = w.Write(raw)
}
