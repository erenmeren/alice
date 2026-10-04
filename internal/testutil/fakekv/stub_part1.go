package fakekv

import "net/http"

// Part-1 placeholders replaced by the identity and fault code of Task 5.

type hold struct{}

func (h *hold) releaseLocked() {}

func (s *Server) serveWithFaults(w http.ResponseWriter, r *http.Request, route http.HandlerFunc) {
	route(w, r)
}

func (s *Server) serveLogin(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) serveIMDS(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}
