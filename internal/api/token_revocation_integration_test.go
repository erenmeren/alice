//go:build integration

package api

import (
	"net/http"
	"testing"
)

// TestAdminIncidentActionsRevokeAPITokens (AUD-12): over HTTP, an administrator's "set a new
// password" and "sign out everywhere" each make the user's API tokens answer 401 on the very
// next request; the user changing their own password keeps them. Both answers stay 204.
func TestAdminIncidentActionsRevokeAPITokens(t *testing.T) {
	s, adminBrowser, admin := installed(t)
	olga := s.createUser(adminBrowser, admin, "olga", "operator", operatorPassword)
	browser := s.client("198.51.100.60")
	s.firstSignIn(browser, olga)
	api := s.client("198.51.100.61")
	use := func(token string) int {
		api.bearer = token
		return api.do(http.MethodGet, "/api/v1/version", nil).Code
	}

	// Own password change: the token keeps working.
	token, _ := createToken(t, s, browser, olga, "read", 30)
	requireStatus(t, browser.do(http.MethodPost, "/api/v1/auth/password", map[string]string{
		"current_password": operatorPassword, "new_password": "olga's next long password",
	}), http.StatusOK)
	olga.password = "olga's next long password"
	if code := use(token); code != http.StatusOK {
		t.Fatalf("token after the user's own password change: %d, want 200", code)
	}

	// Sign out everywhere.
	s.stepUp(adminBrowser, admin)
	requireStatus(t, adminBrowser.do(http.MethodPost, "/api/v1/users/"+olga.id+"/actions/revoke-sessions", nil), http.StatusNoContent)
	requireError(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")

	// Set a new password.
	s.signIn(browser, olga)
	token, _ = createToken(t, s, browser, olga, "read", 30)
	if code := use(token); code != http.StatusOK {
		t.Fatalf("new token: %d, want 200", code)
	}
	s.stepUp(adminBrowser, admin)
	requireStatus(t, adminBrowser.do(http.MethodPost, "/api/v1/users/"+olga.id+"/actions/reset-password",
		map[string]string{"password": "a password the admin chose"}), http.StatusNoContent)
	requireError(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
}
