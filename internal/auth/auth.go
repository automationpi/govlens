// Package auth provides pluggable authentication (any OIDC provider — Entra ID,
// Google, Okta… — or a local dev provider) plus signed-cookie sessions and
// role resolution. Providers implement one interface, so swapping IdPs is config,
// not code.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/automationpi/govlens/internal/store"
)

// Identity is who a provider says the user is.
type Identity struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Oid      string `json:"oid,omitempty"` // Azure AD object id (grant target); empty for non-Entra providers
	Provider string `json:"prov"`
}

// Provider is one authentication backend. OIDCProvider and DevProvider implement it.
type Provider interface {
	Name() string
	// AuthURL is where the browser is sent to authenticate (OIDC authorize URL,
	// or the local dev-login form).
	AuthURL(state string) string
	// Exchange completes the flow from the callback request and returns the identity.
	Exchange(ctx context.Context, r *http.Request) (*Identity, error)
}

// RoleStore is the app's source of truth for who has which scoped role.
type RoleStore interface {
	UpsertAppUser(ctx context.Context, email, name string) error
	UserGrants(ctx context.Context, email string) (map[string][]string, error) // scope -> roles
}

// User is the resolved current user: identity + scoped grants (scope '*' = global).
type User struct {
	Identity
	Grants map[string][]string
}

func (u *User) has(scope, role string) bool {
	for _, r := range u.Grants[scope] {
		if r == role {
			return true
		}
	}
	return false
}

// IsAdmin / IsApprover refer to TENANT-WIDE (global) grants.
func (u *User) IsAdmin() bool    { return u.has("*", "admin") }
func (u *User) IsApprover() bool { return u.has("*", "approver") || u.IsAdmin() }

// IsAnyAdmin is true for a global admin or any subscription-scoped admin
// (used to gate access to the admin page).
func (u *User) IsAnyAdmin() bool {
	for _, roles := range u.Grants {
		for _, r := range roles {
			if r == "admin" {
				return true
			}
		}
	}
	return false
}

// IsAdminOf reports whether the user can administer a scope (global admin, or
// admin of that specific subscription).
func (u *User) IsAdminOf(scope string) bool { return u.IsAdmin() || u.has(scope, "admin") }

// AdminScopes lists the scopes where the user holds 'admin' ('*' = global).
func (u *User) AdminScopes() []string {
	var out []string
	for scope, roles := range u.Grants {
		for _, r := range roles {
			if r == "admin" {
				out = append(out, scope)
			}
		}
	}
	return out
}

// CanApprove reports whether the user may approve a request at requestScope:
// a global approver/admin, or an approver/admin scoped to that subscription.
// Tenant-level (directory) requests require a global grant.
func (u *User) CanApprove(requestScope string) bool {
	if u.IsApprover() {
		return true
	}
	sub := store.SubscriptionOfScope(requestScope)
	if sub == "" {
		return false
	}
	return u.has(sub, "approver") || u.has(sub, "admin")
}

// Roles returns a flat label list for display (e.g. "admin", "sub:… approver").
func (u *User) Roles() []string {
	var out []string
	for scope, roles := range u.Grants {
		for _, r := range roles {
			if scope == "*" {
				out = append(out, r)
			} else {
				out = append(out, "sub:"+short(scope)+" "+r)
			}
		}
	}
	return out
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// Auth ties a provider, a signing secret, and the role store together.
type Auth struct {
	Enabled     bool
	Provider    Provider
	store       RoleStore
	secret      []byte
	adminEmails map[string]bool
	cookieName  string
}

const cookieName = "govlens_session"

// NewFromEnv builds Auth from environment:
//
//	GOVLENS_AUTH            off (default) | entra | oidc | dev
//	GOVLENS_SESSION_SECRET  HMAC secret for session cookies (required unless off)
//	GOVLENS_ADMIN_EMAILS    comma-separated bootstrap admins
//	GOVLENS_ENTRA_TENANT    tenant id (entra); or OIDC_ISSUER for a generic issuer
//	OIDC_CLIENT_ID / OIDC_CLIENT_SECRET / OIDC_REDIRECT_URL
func NewFromEnv(ctx context.Context, store RoleStore) (*Auth, error) {
	mode := strings.ToLower(os.Getenv("GOVLENS_AUTH"))
	a := &Auth{store: store, cookieName: cookieName, adminEmails: map[string]bool{}}
	for _, e := range strings.Split(os.Getenv("GOVLENS_ADMIN_EMAILS"), ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			a.adminEmails[e] = true
		}
	}
	if mode == "" || mode == "off" {
		return a, nil // auth disabled — local/dev use
	}
	secret := os.Getenv("GOVLENS_SESSION_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("GOVLENS_SESSION_SECRET is required when GOVLENS_AUTH=%s", mode)
	}
	a.secret = []byte(secret)

	switch mode {
	case "dev":
		a.Provider = &DevProvider{}
	case "entra", "oidc":
		p, err := newOIDCFromEnv(ctx, mode)
		if err != nil {
			return nil, err
		}
		a.Provider = p
	default:
		return nil, fmt.Errorf("unknown GOVLENS_AUTH=%q", mode)
	}
	a.Enabled = true
	return a, nil
}

// --- sessions (signed cookie) ---

type session struct {
	Identity
	Exp int64 `json:"exp"`
}

func (a *Auth) sign(b []byte) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *Auth) verify(v string) ([]byte, bool) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return nil, false
	}
	b, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return nil, false
	}
	m := hmac.New(sha256.New, a.secret)
	m.Write(b)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return nil, false
	}
	return b, true
}

// IssueSession sets the session cookie for an identity.
func (a *Auth) IssueSession(w http.ResponseWriter, id Identity) {
	s := session{Identity: id, Exp: time.Now().Add(8 * time.Hour).Unix()}
	b, _ := json.Marshal(s)
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName, Value: a.sign(b), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 3600,
	})
}

// Clear removes the session cookie.
func (a *Auth) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: a.cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
}

// Current resolves the logged-in user (identity + roles). When auth is disabled
// it returns a synthetic local admin so the app is fully usable in dev.
func (a *Auth) Current(ctx context.Context, r *http.Request) *User {
	if !a.Enabled {
		return &User{Identity: Identity{Email: "local@dev", Name: "Local (auth off)", Provider: "none"},
			Grants: map[string][]string{"*": {"admin", "approver"}}}
	}
	c, err := r.Cookie(a.cookieName)
	if err != nil {
		return nil
	}
	b, ok := a.verify(c.Value)
	if !ok {
		return nil
	}
	var s session
	if json.Unmarshal(b, &s) != nil || s.Exp < time.Now().Unix() {
		return nil
	}
	return &User{Identity: s.Identity, Grants: a.grantsFor(ctx, s.Email)}
}

// grantsFor merges stored scoped grants with bootstrap (global) admin emails.
func (a *Auth) grantsFor(ctx context.Context, email string) map[string][]string {
	grants, _ := a.store.UserGrants(ctx, email)
	if grants == nil {
		grants = map[string][]string{}
	}
	if a.adminEmails[strings.ToLower(email)] {
		has := false
		for _, r := range grants["*"] {
			if r == "admin" {
				has = true
			}
		}
		if !has {
			grants["*"] = append(grants["*"], "admin")
		}
	}
	return grants
}

// CompleteLogin runs the provider exchange, records the user, and issues a session.
func (a *Auth) CompleteLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Identity, error) {
	id, err := a.Provider.Exchange(ctx, r)
	if err != nil {
		return nil, err
	}
	if id.Email == "" {
		return nil, fmt.Errorf("provider returned no email")
	}
	_ = a.store.UpsertAppUser(ctx, strings.ToLower(id.Email), id.Name)
	a.IssueSession(w, *id)
	return id, nil
}
