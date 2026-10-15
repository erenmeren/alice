package web

import "net/http"

// pages registers the signed-in pages: customers, requests, licenses and downloads. Task 4 fills
// it; until then only the minimal home page of the "/" fallback exists.
func (s *Server) pages(mux *http.ServeMux) {}
