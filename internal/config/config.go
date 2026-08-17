// Package config loads a single YAML file that describes an entire GovLens
// deployment: the database connection, authentication, the service principals
// (each cert- or secret-based), and which modules run. Any string value may use
// ${ENV_VAR} interpolation so secrets can live in the environment instead of the
// file. The database is always external — GovLens never manages one.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Tenant   Tenant   `yaml:"tenant"`
	Database Database `yaml:"database"`
	Server   Server   `yaml:"server"`
	Auth     Auth     `yaml:"auth"`
	SPs      SPs      `yaml:"service_principals"`
	Modules  Modules  `yaml:"modules"`
}

type Tenant struct {
	Label   string `yaml:"label"`   // stable key; default = the SP tenant id
	Display string `yaml:"display"` // friendly name; default = Entra org name
}

type Database struct {
	DSN string `yaml:"dsn"` // bring-your-own Postgres connection string (required)
}

type Server struct {
	Addr string `yaml:"addr"` // listen address, default :8080
}

type Auth struct {
	Mode             string   `yaml:"mode"` // entra | oidc | dev | off
	EntraTenant      string   `yaml:"entra_tenant"`
	OIDCIssuer       string   `yaml:"oidc_issuer"`
	OIDCClientID     string   `yaml:"oidc_client_id"`
	OIDCClientSecret string   `yaml:"oidc_client_secret"`
	RedirectURL      string   `yaml:"redirect_url"`
	SessionSecret    string   `yaml:"session_secret"`
	AdminEmails      []string `yaml:"admin_emails"`
}

// SP is one service principal with exactly one credential (secret preferred if set).
type SP struct {
	AppID     string `yaml:"app_id"`
	Tenant    string `yaml:"tenant"`     // default = Auth.EntraTenant
	Cert      string `yaml:"cert"`       // path | inline PEM | base64 PEM
	Secret    string `yaml:"secret"`     // client secret (alternative to cert)
	RootScope string `yaml:"root_scope"` // grant SP only
}

// TenantOr returns the SP's tenant, defaulting to def when unset.
func (s SP) TenantOr(def string) string {
	if s.Tenant != "" {
		return s.Tenant
	}
	return def
}

// Configured reports whether the SP has an id and a credential.
func (s SP) Configured() bool {
	return s.AppID != "" && (s.Cert != "" || s.Secret != "")
}

type SPs struct {
	Collector  SP `yaml:"collector"`
	Remediator SP `yaml:"remediator"`
	Grant      SP `yaml:"grant"`
}

// Module toggles one background worker.
type Module struct {
	Enabled  bool `yaml:"enabled"`
	Execute  bool `yaml:"execute"`  // real changes vs dry-run (remediator/grant)
	Interval int  `yaml:"interval"` // seconds between cycles
}

type Modules struct {
	Collector  Module `yaml:"collector"`
	Remediator Module `yaml:"remediator"`
	Grant      Module `yaml:"grant"`
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${VAR} with the environment value (bare $ is left untouched,
// so DSN passwords containing $ are safe). Unknown vars expand to empty.
func expandEnv(b []byte) []byte {
	return envRef.ReplaceAllFunc(b, func(m []byte) []byte {
		name := envRef.FindSubmatch(m)[1]
		return []byte(os.Getenv(string(name)))
	})
}

// Load reads, interpolates, parses, defaults, and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(expandEnv(raw), &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Addr == "" {
		c.Server.Addr = ":8080"
	}
	if c.Auth.Mode == "" {
		c.Auth.Mode = "off"
	}
	if c.Modules.Collector.Interval == 0 {
		c.Modules.Collector.Interval = 3600
	}
	if c.Modules.Remediator.Interval == 0 {
		c.Modules.Remediator.Interval = 3600
	}
	if c.Modules.Grant.Interval == 0 {
		c.Modules.Grant.Interval = 300
	}
}

func (c *Config) validate() error {
	if strings.TrimSpace(c.Database.DSN) == "" {
		return fmt.Errorf("database.dsn is required (GovLens uses your own Postgres)")
	}
	switch c.Auth.Mode {
	case "off", "dev":
	case "entra":
		if c.Auth.EntraTenant == "" || c.Auth.OIDCClientID == "" || c.Auth.RedirectURL == "" {
			return fmt.Errorf("auth.mode=entra needs entra_tenant, oidc_client_id, redirect_url")
		}
	case "oidc":
		if c.Auth.OIDCIssuer == "" || c.Auth.OIDCClientID == "" || c.Auth.RedirectURL == "" {
			return fmt.Errorf("auth.mode=oidc needs oidc_issuer, oidc_client_id, redirect_url")
		}
	default:
		return fmt.Errorf("auth.mode must be entra|oidc|dev|off, got %q", c.Auth.Mode)
	}
	if c.Auth.Mode != "off" && c.Auth.SessionSecret == "" {
		return fmt.Errorf("auth.session_secret is required when auth is enabled")
	}
	// Enabled modules need a usable service principal.
	for _, m := range []struct {
		name string
		on   bool
		sp   SP
	}{
		{"collector", c.Modules.Collector.Enabled, c.SPs.Collector},
		{"remediator", c.Modules.Remediator.Enabled, c.SPs.Remediator},
		{"grant", c.Modules.Grant.Enabled, c.SPs.Grant},
	} {
		if m.on && !m.sp.Configured() {
			return fmt.Errorf("module %s is enabled but its service principal needs app_id + cert/secret", m.name)
		}
	}
	if c.Modules.Grant.Enabled && c.SPs.Grant.RootScope == "" {
		return fmt.Errorf("grant module needs service_principals.grant.root_scope")
	}
	return nil
}
