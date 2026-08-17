package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider works with any OpenID Connect issuer (Entra ID, Google, Okta, …).
type OIDCProvider struct {
	name     string
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// newOIDCFromEnv builds an OIDC provider. For mode "entra" the issuer is derived
// from GOVLENS_ENTRA_TENANT; for "oidc" it comes from OIDC_ISSUER.
func newOIDCFromEnv(ctx context.Context, mode string) (*OIDCProvider, error) {
	issuer := os.Getenv("OIDC_ISSUER")
	if mode == "entra" {
		tenant := os.Getenv("GOVLENS_ENTRA_TENANT")
		if tenant == "" {
			return nil, fmt.Errorf("GOVLENS_ENTRA_TENANT is required for GOVLENS_AUTH=entra")
		}
		issuer = "https://login.microsoftonline.com/" + tenant + "/v2.0"
	}
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirect := os.Getenv("OIDC_REDIRECT_URL")
	if issuer == "" || clientID == "" || redirect == "" {
		return nil, fmt.Errorf("OIDC needs issuer, OIDC_CLIENT_ID and OIDC_REDIRECT_URL")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery (%s): %w", issuer, err)
	}
	return &OIDCProvider{
		name: mode,
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirect,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

func (p *OIDCProvider) Name() string { return p.name }

func (p *OIDCProvider) AuthURL(state string) string {
	return p.oauth.AuthCodeURL(state)
}

func (p *OIDCProvider) Exchange(ctx context.Context, r *http.Request) (*Identity, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("missing authorization code")
	}
	tok, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in response")
	}
	idTok, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		Oid               string `json:"oid"` // Azure AD object id — the grant target
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return nil, err
	}
	email := claims.Email
	if email == "" {
		email = claims.PreferredUsername // Entra often puts UPN here
	}
	return &Identity{Subject: claims.Sub, Email: email, Name: claims.Name, Oid: claims.Oid, Provider: p.name}, nil
}
