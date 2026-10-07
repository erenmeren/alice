package fakesmtp

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type mailhogPath struct{ Mailbox, Domain string }

type mailhogItem struct {
	ID      string
	From    mailhogPath
	To      []mailhogPath
	Content struct {
		Headers map[string][]string
		Body    string
	}
	Raw struct {
		From string
		To   []string
		Data string
	}
}

func pathOf(a string) mailhogPath {
	box, dom, _ := strings.Cut(a, "@")
	return mailhogPath{Mailbox: box, Domain: dom}
}

// Handler serves the MailHog API subset the e2e journeys and an operator's tools use: GET /api/v2/messages (the
// MailHog v2 shape; Content.Body is the decoded body) and DELETE /api/v1/messages.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/messages", func(w http.ResponseWriter, _ *http.Request) {
		msgs := s.Messages()
		items := make([]mailhogItem, 0, len(msgs))
		for i, m := range msgs {
			it := mailhogItem{ID: strconv.Itoa(i + 1), From: pathOf(m.From)}
			for _, t := range m.To {
				it.To = append(it.To, pathOf(t))
			}
			it.Content.Headers = map[string][]string{"Subject": {m.Subject}, "From": {m.From}, "To": m.To}
			it.Content.Body = m.Body
			it.Raw.From, it.Raw.To, it.Raw.Data = m.From, m.To, m.Raw
			items = append(items, it)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"total": len(items), "count": len(items), "start": 0, "items": items})
	})
	mux.HandleFunc("DELETE /api/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		s.Clear()
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
