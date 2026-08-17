// Package collect is the lean, dependency-free collector: it authenticates as
// the read-only service principal (certificate client-assertion) and pulls
// governance data straight from the Azure ARM and Microsoft Graph REST APIs,
// writing runs directly into the store — no PowerShell, no files.
package collect

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// SP holds the service-principal identity and one credential: either a
// certificate (client-assertion) or a client secret.
type SP struct {
	TenantID string
	ClientID string

	cert   *x509.Certificate
	key    *rsa.PrivateKey
	secret string // set → authenticate with a client secret instead of the cert
}

// NewSPFromCred builds an SP from whichever credential is provided: a client
// `secret` (preferred if non-empty), else a certificate given as `cert` — a file
// path, an inline PEM, or base64-encoded PEM. Lets operators pick cert or secret.
func NewSPFromCred(tenantID, clientID, cert, secret string) (*SP, error) {
	if s := strings.TrimSpace(secret); s != "" {
		return &SP{TenantID: tenantID, ClientID: clientID, secret: s}, nil
	}
	pemBytes, err := resolvePEM(cert)
	if err != nil {
		return nil, err
	}
	return newSPFromPEM(tenantID, clientID, pemBytes)
}

// NewSPFromSecret builds an SP that authenticates with a client secret.
func NewSPFromSecret(tenantID, clientID, secret string) (*SP, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("empty client secret")
	}
	return &SP{TenantID: tenantID, ClientID: clientID, secret: secret}, nil
}

// resolvePEM turns a cert config value into PEM bytes: inline PEM, base64 PEM,
// or a file path.
func resolvePEM(cert string) ([]byte, error) {
	cert = strings.TrimSpace(cert)
	if cert == "" {
		return nil, fmt.Errorf("no certificate or secret provided")
	}
	if strings.Contains(cert, "-----BEGIN") {
		return []byte(cert), nil
	}
	if b, err := base64.StdEncoding.DecodeString(cert); err == nil && strings.Contains(string(b), "-----BEGIN") {
		return b, nil
	}
	b, err := os.ReadFile(cert)
	if err != nil {
		return nil, fmt.Errorf("read cert %q: %w", cert, err)
	}
	return b, nil
}

// NewSP loads the PEM (cert + private key, as produced by
// `az ad app credential reset --create-cert`).
func NewSP(tenantID, clientID, certPath string) (*SP, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	return newSPFromPEM(tenantID, clientID, pemBytes)
}

// newSPFromPEM parses a cert+key PEM into an SP.
func newSPFromPEM(tenantID, clientID string, pemBytes []byte) (*SP, error) {
	sp := &SP{TenantID: tenantID, ClientID: clientID}
	var err error
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if sp.cert == nil {
				sp.cert, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("parse cert: %w", err)
				}
			}
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse pkcs8 key: %w", err)
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is not RSA")
			}
			sp.key = rk
		case "RSA PRIVATE KEY":
			sp.key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse pkcs1 key: %w", err)
			}
		}
	}
	if sp.cert == nil || sp.key == nil {
		return nil, fmt.Errorf("PEM must contain both a CERTIFICATE and a PRIVATE KEY")
	}
	return sp, nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// clientAssertion builds a signed JWT proving possession of the cert's key.
func (sp *SP) clientAssertion() (string, error) {
	tokenEndpoint := "https://login.microsoftonline.com/" + sp.TenantID + "/oauth2/v2.0/token"
	thumb := sha1.Sum(sp.cert.Raw)
	header := map[string]string{"alg": "RS256", "typ": "JWT", "x5t": b64url(thumb[:])}
	now := time.Now()
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	claims := map[string]any{
		"aud": tokenEndpoint,
		"iss": sp.ClientID,
		"sub": sp.ClientID,
		"jti": b64url(jti),
		"nbf": now.Unix(),
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	hj, _ := json.Marshal(header)
	cj, _ := json.Marshal(claims)
	signingInput := b64url(hj) + "." + b64url(cj)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, sp.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64url(sig), nil
}

// Token fetches an app-only access token for the given resource scope
// (e.g. "https://management.azure.com/.default" or
// "https://graph.microsoft.com/.default").
func (sp *SP) Token(ctx context.Context, scope string) (string, error) {
	form := url.Values{
		"client_id":  {sp.ClientID},
		"scope":      {scope},
		"grant_type": {"client_credentials"},
	}
	if sp.secret != "" {
		form.Set("client_secret", sp.secret)
	} else {
		assertion, err := sp.clientAssertion()
		if err != nil {
			return "", err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	}
	endpoint := "https://login.microsoftonline.com/" + sp.TenantID + "/oauth2/v2.0/token"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("token error (%d): %s: %s", resp.StatusCode, out.Error, firstLine(out.ErrorDesc))
	}
	return out.AccessToken, nil
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
