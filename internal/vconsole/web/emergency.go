package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/vconsole/store"
	"alice/internal/vconsole/webuser"
)

// Emergency extensions (docs/superpowers/rulings/vendor-emergency-extension.md): a short license
// for an installation whose license lapsed, asked for from the licenses page. The form shows what
// is carried over from the installation's latest license and takes only the term and a reason; the
// store reads the carried-over content itself, so nothing of it comes from the browser. The
// request is signed like any other (vendor-console issue, the YubiKey rules unchanged).

type emergencyData struct {
	Basis   store.EmergencyBasis
	Days    string
	Reason  string
	Error   string
	Max     int
	MaxLen  int
	Default int
}

// canExtend says whether the licenses page offers an extension for r: the installation's latest
// license, not revoked, ending before an extension signed today could end. The store decides.
func canExtend(r store.LicenseRow, now time.Time) bool {
	limit := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, store.MaxEmergencyDays)
	return r.Latest && r.RevokedAt == nil && r.ValidUntil.Before(limit)
}

func (s *Server) renderEmergency(w http.ResponseWriter, r *http.Request, u webuser.User, status int, id string, d emergencyData) {
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		d.Basis, err = store.GetEmergencyBasis(r.Context(), tx, id)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, "read license for an emergency extension", err)
		return
	}
	d.Max, d.MaxLen, d.Default = store.MaxEmergencyDays, store.MaxReasonLen, store.DefaultEmergencyDays
	s.renderUser(w, r, status, "request_emergency", u, d)
}

// emergencyPage is /requests/emergency?license=<id>: the form for the installation of that license.
// An odd, unknown or revoked ID is 404.
func (s *Server) emergencyPage(w http.ResponseWriter, r *http.Request, u webuser.User) {
	id := r.URL.Query().Get("license")
	if !licenseIDPattern.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	s.renderEmergency(w, r, u, http.StatusOK, id, emergencyData{Days: strconv.Itoa(store.DefaultEmergencyDays)})
}

func (s *Server) emergencyAdd(w http.ResponseWriter, r *http.Request, u webuser.User) {
	if !s.readForm(w, r) {
		return
	}
	id := r.PostFormValue("license")
	if !licenseIDPattern.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	d := emergencyData{Days: r.PostFormValue("days"), Reason: r.PostFormValue("reason")}
	refuse := func(msg string) {
		d.Error = msg
		s.renderEmergency(w, r, u, http.StatusUnprocessableEntity, id, d)
	}
	days := 0
	if v := strings.TrimSpace(d.Days); v != "" {
		var err error
		if days, err = strconv.Atoi(v); err != nil {
			refuse(fmt.Sprintf("Days must be a whole number from 1 to %d.", store.MaxEmergencyDays))
			return
		}
	}
	var reqID int64
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		reqID, err = store.AddEmergencyRequest(r.Context(), tx, store.NewEmergency{LicenseID: id, Days: days, Reason: d.Reason},
			s.cfg.Clock.Now())
		return err
	})
	var invalid *store.InvalidError
	switch {
	case errors.As(err, &invalid):
		refuse(invalid.Err.Error())
		return
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		s.serverError(w, "add emergency request", err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", reqID), http.StatusSeeOther)
}
