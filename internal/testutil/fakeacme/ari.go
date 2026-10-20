package fakeacme

import (
	"net/http"
	"time"
)

// ariRetryAfter is the Retry-After the fake sends with renewal information (RFC 9773 section 4.2).
const ariRetryAfter = "21600"

// handleARI answers GET renewalInfo/<certID>. The suggested window is the one set for this certificate
// (SetARIWindowFor), else the configured one (absolute, or relative to the certificate's expiry) or, by
// default, the last third of the certificate's life widened to one twelfth of it (GUESS: public CAs
// choose their own).
func (s *Server) handleARI(w http.ResponseWriter, r *http.Request, _ *jwsReq) {
	s.mu.Lock()
	c := s.st.byARI[r.PathValue("certid")]
	own, hasOwn := s.st.ariWindows[r.PathValue("certid")]
	cfg := s.cfg
	s.mu.Unlock()
	if c == nil {
		s.writeProblem(w, malformed(http.StatusNotFound, "no such certificate"))
		return
	}
	start, end := cfg.ariStart, cfg.ariEnd
	if hasOwn {
		start, end = own.start, own.end
	}
	if start.IsZero() {
		life := c.leaf.NotAfter.Sub(c.leaf.NotBefore)
		before, length := cfg.ariBefore, cfg.ariLength
		if before <= 0 {
			before = life / 3
		}
		if length <= 0 {
			length = max(life/12, time.Minute)
		}
		start = c.leaf.NotAfter.Add(-before)
		end = start.Add(length)
	}
	w.Header().Set("Retry-After", ariRetryAfter)
	writeJSON(w, http.StatusOK, map[string]any{
		"suggestedWindow": map[string]string{"start": start.UTC().Format(time.RFC3339), "end": end.UTC().Format(time.RFC3339)},
	})
}
