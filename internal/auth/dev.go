package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// DevProvider is a local, no-IdP provider for development and for demonstrating
// that any provider plugs into the same interface. It "authenticates" whatever
// email is submitted to the dev-login form. NEVER enable in production.
type DevProvider struct{}

func (DevProvider) Name() string { return "dev" }

// AuthURL points at the local dev-login form (served by the web layer).
func (DevProvider) AuthURL(state string) string {
	return "/auth/devform?state=" + state
}

func (DevProvider) Exchange(_ context.Context, r *http.Request) (*Identity, error) {
	_ = r.ParseForm()
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		return nil, fmt.Errorf("dev login: email required")
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = email
	}
	return &Identity{Subject: "dev:" + email, Email: email, Name: name, Provider: "dev"}, nil
}
