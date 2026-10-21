package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"alice/internal/authz/services"
)

// Directory groups (R49 Phase 3, R54; design §6.1, §8.1): the groups of an SSO provider or a directory that role
// bindings (and, from Phase 4, owner teams) name. Reading them is users.read, declaring and removing them
// access.manage, as the role bindings (accessRoutes).

// maxDirectoryGroupBody bounds the body of a new directory group (a DN value is at most 1024 characters).
const maxDirectoryGroupBody = 8 << 10

type directoryGroupDTO struct {
	ID            uuid.UUID  `json:"id"`
	Source        string     `json:"source"`
	ProviderID    *uuid.UUID `json:"provider_id"`
	DirectoryID   *uuid.UUID `json:"directory_id"`
	SourceName    string     `json:"source_name"`
	Value         string     `json:"value"`
	Label         string     `json:"label"`
	Members       int        `json:"members"`
	Bindings      int        `json:"bindings"`
	CreatedBy     *uuid.UUID `json:"created_by"`
	CreatedByName string     `json:"created_by_name"`
	CreatedAt     time.Time  `json:"created_at"`
}

func directoryGroupJSON(g services.DirectoryGroup) directoryGroupDTO {
	return directoryGroupDTO{ID: g.ID, Source: g.Source, ProviderID: g.ProviderID, DirectoryID: g.DirectoryID, SourceName: g.SourceName,
		Value: g.Value, Label: g.Label, Members: g.Members, Bindings: g.Bindings, CreatedBy: g.CreatedBy, CreatedByName: g.CreatedByName,
		CreatedAt: g.CreatedAt.UTC()}
}

// seenGroupDTO is a group value seen at sign-ins: how many people had it and the declared group of that value, if any.
type seenGroupDTO struct {
	Source           string     `json:"source"`
	ProviderID       *uuid.UUID `json:"provider_id"`
	DirectoryID      *uuid.UUID `json:"directory_id"`
	SourceName       string     `json:"source_name"`
	Value            string     `json:"value"`
	Users            int        `json:"users"`
	DirectoryGroupID *uuid.UUID `json:"directory_group_id"`
}

func (s *server) listDirectoryGroups(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	groups, seen, err := s.deps.Services.DirectoryGroups(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]directoryGroupDTO, 0, len(groups))
	for _, g := range groups {
		items = append(items, directoryGroupJSON(g))
	}
	values := make([]seenGroupDTO, 0, len(seen))
	for _, g := range seen {
		values = append(values, seenGroupDTO{Source: g.Source, ProviderID: g.ProviderID, DirectoryID: g.DirectoryID, SourceName: g.SourceName,
			Value: g.Value, Users: g.Users, DirectoryGroupID: g.GroupID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "seen": values})
}

func (s *server) createDirectoryGroup(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	var req struct {
		Source      string     `json:"source"`
		ProviderID  *uuid.UUID `json:"provider_id"`
		DirectoryID *uuid.UUID `json:"directory_id"`
		Value       string     `json:"value"`
		Label       string     `json:"label"`
	}
	if !s.decodeExact(w, r, &req, maxDirectoryGroupBody, "source", "provider_id", "directory_id", "value", "label") {
		return
	}
	g, err := s.deps.Services.CreateDirectoryGroup(r.Context(), s.serviceActor(r), services.DirectoryGroupInput{Source: req.Source,
		ProviderID: req.ProviderID, DirectoryID: req.DirectoryID, Value: req.Value, Label: req.Label})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/directory-groups/"+g.ID.String())
	writeJSON(w, http.StatusCreated, directoryGroupJSON(g))
}

func (s *server) deleteDirectoryGroup(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrACCGroupNotFound)
		return
	}
	removed, err := s.deps.Services.DeleteDirectoryGroup(r.Context(), s.serviceActor(r), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"bindings_removed": removed.Bindings, "owners_removed": removed.Owners})
}
