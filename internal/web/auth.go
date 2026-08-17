package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/automationpi/govlens/internal/auth"
)

type ctxKey int

const userKey ctxKey = 0

func randState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// authMiddleware requires a logged-in user for everything except public routes
// when auth is enabled. When auth is off, Current() returns a synthetic local
// admin so the app stays fully usable.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		u := s.auth.Current(r.Context(), r)
		if s.auth.Enabled && u == nil {
			// Only redirect real page navigations to login. Sub-resource requests
			// (favicon, assets) and API/fetch calls get 401 — otherwise each such
			// request would re-run /auth/login and overwrite the CSRF state cookie.
			if !strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

func isPublicPath(p string) bool {
	switch p {
	case "/healthz", "/favicon.ico", "/favicon.svg", "/auth/login", "/auth/callback", "/auth/devform":
		return true
	}
	return false
}

// userOf returns the current user attached by the middleware.
func userOf(r *http.Request) *auth.User {
	u, _ := r.Context().Value(userKey).(*auth.User)
	return u
}

// requireRole writes 403 and returns false if the user lacks the role.
func requireRole(w http.ResponseWriter, r *http.Request, role string) (*auth.User, bool) {
	u := userOf(r)
	if u == nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return nil, false
	}
	ok := false
	switch role {
	case "":
		ok = true // any authenticated user
	case "admin":
		ok = u.IsAdmin() // global admin
	case "anyadmin":
		ok = u.IsAnyAdmin() // global or subscription-scoped admin
	case "approver":
		ok = u.IsApprover() // global approver
	}
	if !ok {
		http.Error(w, "forbidden: requires "+role+" role", http.StatusForbidden)
		return nil, false
	}
	return u, true
}

func (s *Server) authRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/login", s.authLogin)
	mux.HandleFunc("/auth/callback", s.authCallback)
	mux.HandleFunc("/auth/logout", s.authLogout)
	mux.HandleFunc("/auth/devform", s.authDevForm)
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Enabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	state := randState()
	setShort(w, "oauth_state", state)
	if next := r.URL.Query().Get("next"); next != "" {
		setShort(w, "oauth_next", next)
	}
	http.Redirect(w, r, s.auth.Provider.AuthURL(state), http.StatusFound)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Enabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// CSRF: state from query (OIDC) or form (dev) must match the cookie.
	state := r.URL.Query().Get("state")
	if state == "" {
		_ = r.ParseForm()
		state = r.FormValue("state")
	}
	if c, err := r.Cookie("oauth_state"); err != nil || c.Value == "" || c.Value != state {
		http.Error(w, "invalid or missing state", http.StatusBadRequest)
		return
	}
	if _, err := s.auth.CompleteLogin(r.Context(), w, r); err != nil {
		http.Error(w, "login failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	next := "/"
	if c, err := r.Cookie("oauth_next"); err == nil && strings.HasPrefix(c.Value, "/") {
		next = c.Value
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.Clear(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// authDevForm serves the local dev-login form (dev provider only).
func (s *Server) authDevForm(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Enabled || s.auth.Provider.Name() != "dev" {
		http.Error(w, "dev login not enabled", http.StatusNotFound)
		return
	}
	s.render(w, "devlogin.html", map[string]string{"State": r.URL.Query().Get("state")})
}

func setShort(w http.ResponseWriter, name, val string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 600})
}
