package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// A service's owner team (R56, design §7.1, §8.1): read by everyone who sees the service, replaced by a global
// Administrator (services.manage, step-up, never a token). At most services.MaxOwnersPerService entries of about 80
// bytes.
const maxServiceOwnersBody = 16 << 10

// serviceOwnerDTO is one owner: a person (user_id, username, display_name, disabled, receives_email) or a directory
// group (directory_group_id, group, members). reaches_service (whether a role of the owner reaches the service, for the
// editor's warning) is shown to a caller who may read people (a global users.read): it tells who holds a role.
type serviceOwnerDTO struct {
	ID               uuid.UUID        `json:"id"`
	Kind             string           `json:"kind"` // "person" or "group"
	UserID           *uuid.UUID       `json:"user_id"`
	Username         string           `json:"username,omitempty"`
	DisplayName      string           `json:"display_name,omitempty"`
	Disabled         bool             `json:"disabled"`
	ReceivesEmail    bool             `json:"receives_email"`
	DirectoryGroupID *uuid.UUID       `json:"directory_group_id"`
	Group            *bindingGroupDTO `json:"group,omitempty"`
	Members          int              `json:"members"`
	ReachesService   *bool            `json:"reaches_service,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
}

type serviceOwnersDTO struct {
	Version int               `json:"version"`
	Items   []serviceOwnerDTO `json:"items"`
}

func serviceOwnersJSON(o services.Owners, showReach bool) serviceOwnersDTO {
	out := serviceOwnersDTO{Version: o.Version, Items: make([]serviceOwnerDTO, 0, len(o.Items))}
	for _, it := range o.Items {
		d := serviceOwnerDTO{ID: it.ID, Kind: "person", UserID: it.UserID, Username: it.Username, DisplayName: it.DisplayName,
			Disabled: it.Disabled, ReceivesEmail: !it.Disabled && it.HasEmail, DirectoryGroupID: it.DirectoryGroupID, Members: it.Members,
			CreatedAt: it.CreatedAt}
		if it.Group != nil {
			d.Kind = "group"
			d.Group = &bindingGroupDTO{Source: it.Group.Source, SourceName: it.Group.SourceName, Value: it.Group.Value, Label: it.Group.Label}
		}
		if showReach {
			reaches := it.ReachesService
			d.ReachesService = &reaches
		}
		out.Items = append(out.Items, d)
	}
	return out
}

// getServiceOwners answers a service's owner team and the service's version (GET /api/v1/services/{id}/owners).
func (s *server) getServiceOwners(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrSVCNotFound)
		return
	}
	o, err := s.deps.Services.Owners(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, serviceOwnersJSON(o, rbac.Decide(rbac.UsersRead, s.subjectOf(r)) == rbac.Allow))
}

// putServiceOwners replaces a service's owner team (PUT /api/v1/services/{id}/owners): {"version": the service's
// version read, "owners": [{"user_id"} | {"directory_group_id"}]}. A stale version is ALC-SVC-0010, an automation
// account ALC-SVC-0019.
func (s *server) putServiceOwners(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrSVCNotFound)
		return
	}
	var req struct {
		Version int `json:"version"`
		Owners  []struct {
			UserID           uuid.UUID `json:"user_id"`
			DirectoryGroupID uuid.UUID `json:"directory_group_id"`
		} `json:"owners"`
	}
	if !s.decodeLimit(w, r, &req, maxServiceOwnersBody) {
		return
	}
	var v validate.Errors
	if req.Version < 1 {
		v.Add("version", validate.Required, nil)
	}
	if req.Owners == nil {
		v.Add("owners", validate.Required, nil)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	in := make([]services.OwnerInput, len(req.Owners))
	for i, o := range req.Owners {
		in[i] = services.OwnerInput{UserID: o.UserID, DirectoryGroupID: o.DirectoryGroupID}
	}
	o, err := s.deps.Services.SetOwners(r.Context(), s.serviceActor(r), id, req.Version, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, serviceOwnersJSON(o, true))
}
