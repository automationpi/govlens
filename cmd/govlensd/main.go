// Command govlensd is the single-container entrypoint. It reads one YAML config
// file and runs the whole GovLens stack — the web app plus whichever background
// workers are enabled (remediator, grant, collector) — against your own external
// Postgres. Each component runs as a supervised child process (restarted on exit).
//
//	govlensd -config /etc/govlens/config.yaml
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/automationpi/govlens/internal/config"
	"github.com/automationpi/govlens/internal/store"
)

func main() {
	cfgPath := flag.String("config", envOr("GOVLENS_CONFIG", "/etc/govlens/config.yaml"), "path to config.yaml")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("govlens: config %s loaded (auth=%s; modules: collector=%v remediator=%v grant=%v)",
		*cfgPath, cfg.Auth.Mode, cfg.Modules.Collector.Enabled, cfg.Modules.Remediator.Enabled, cfg.Modules.Grant.Enabled)

	// Apply the schema once up front so the children don't race on CREATE.
	mctx, mcancel := context.WithTimeout(context.Background(), 60*time.Second)
	// database.init: "reuse" (default) keeps existing data; "fresh" wipes GovLens
	// tables first. Reset runs ONLY here in the launcher, before any child starts.
	initMode := cfg.Database.Init
	if initMode == "" {
		initMode = "reuse"
	}
	if initMode == "fresh" {
		if err := store.Reset(mctx, cfg.Database.DSN); err != nil {
			mcancel()
			log.Fatalf("database reset (init=fresh): %v", err)
		}
		log.Printf("govlens: database init=fresh — dropped existing GovLens tables")
	}
	st, err := store.Open(mctx, cfg.Database.DSN)
	mcancel()
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	st.Close()
	log.Printf("govlens: schema ready (init=%s — existing data %s)", initMode,
		map[string]string{"reuse": "preserved", "fresh": "wiped"}[initMode])

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var wg sync.WaitGroup

	// Sibling binaries live next to this one (both at / in the image).
	self, _ := os.Executable()
	bin := func(name string) string { return filepath.Join(filepath.Dir(self), name) }

	// Web — always on.
	wg.Add(1)
	go supervise(ctx, &wg, "web", bin("web"), nil, webEnv(cfg))

	if cfg.Modules.Remediator.Enabled {
		args := loopArgs(cfg.Modules.Remediator)
		wg.Add(1)
		go supervise(ctx, &wg, "remediator", bin("remediator"), args, spEnv(cfg, cfg.SPs.Remediator, nil))
	}
	if cfg.Modules.Grant.Enabled {
		args := loopArgs(cfg.Modules.Grant)
		env := spEnv(cfg, cfg.SPs.Grant, map[string]string{"GRANT_ROOT_SCOPE": cfg.SPs.Grant.RootScope})
		wg.Add(1)
		go supervise(ctx, &wg, "grantworker", bin("grantworker"), args, env)
	}
	if cfg.Modules.Collector.Enabled {
		wg.Add(1)
		go runCollector(ctx, &wg, cfg, bin("collect"))
	}

	wg.Wait()
	log.Printf("govlens: shutdown complete")
}

// supervise runs a long-lived child, restarting it (with backoff) until ctx ends.
func supervise(ctx context.Context, wg *sync.WaitGroup, name, bin string, args, env []string) {
	defer wg.Done()
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = env
		cmd.Stdout, cmd.Stderr = prefixWriter{name, os.Stdout}, prefixWriter{name, os.Stderr}
		log.Printf("[%s] starting", name)
		err := cmd.Run()
		if ctx.Err() != nil {
			return
		}
		log.Printf("[%s] exited (%v) — restarting in 3s", name, err)
		select {
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}

// runCollector execs the one-shot collector immediately, then on its interval.
func runCollector(ctx context.Context, wg *sync.WaitGroup, cfg *config.Config, collectBin string) {
	defer wg.Done()
	env := spEnv(cfg, cfg.SPs.Collector, nil)
	run := func() {
		var args []string
		if cfg.Tenant.Label != "" {
			args = append(args, "-tenant", cfg.Tenant.Label)
		}
		if cfg.Tenant.Display != "" {
			args = append(args, "-display", cfg.Tenant.Display)
		}
		cmd := exec.CommandContext(ctx, collectBin, args...)
		cmd.Env = env
		cmd.Stdout, cmd.Stderr = prefixWriter{"collector", os.Stdout}, prefixWriter{"collector", os.Stderr}
		if err := cmd.Run(); err != nil && ctx.Err() == nil {
			log.Printf("[collector] error: %v", err)
		}
	}
	run()
	t := time.NewTicker(time.Duration(cfg.Modules.Collector.Interval) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func loopArgs(m config.Module) []string {
	args := []string{"-interval", strconv.Itoa(m.Interval)}
	if m.Execute {
		args = append(args, "-execute")
	}
	return args
}

// webEnv derives the web server's environment from config.
func webEnv(cfg *config.Config) []string {
	tenant := cfg.Tenant.Label
	if tenant == "" {
		tenant = "example"
	}
	e := append(os.Environ(),
		"DATABASE_URL="+cfg.Database.DSN,
		"ADDR="+cfg.Server.Addr,
		"TENANT="+tenant,
		"GOVLENS_AUTH="+cfg.Auth.Mode,
		"GOVLENS_ENTRA_TENANT="+cfg.Auth.EntraTenant,
		"OIDC_ISSUER="+cfg.Auth.OIDCIssuer,
		"OIDC_CLIENT_ID="+cfg.Auth.OIDCClientID,
		"OIDC_CLIENT_SECRET="+cfg.Auth.OIDCClientSecret,
		"OIDC_REDIRECT_URL="+cfg.Auth.RedirectURL,
		"GOVLENS_SESSION_SECRET="+cfg.Auth.SessionSecret,
		"GOVLENS_ADMIN_EMAILS="+strings.Join(cfg.Auth.AdminEmails, ","),
	)
	return e
}

// spEnv derives a worker's environment: DB + the SP's identity and credential
// (cert or secret), plus any extras. The child picks cert vs secret itself.
func spEnv(cfg *config.Config, sp config.SP, extra map[string]string) []string {
	e := append(os.Environ(),
		"DATABASE_URL="+cfg.Database.DSN,
		"AZURE_TENANT_ID="+sp.TenantOr(cfg.Auth.EntraTenant),
		"AZURE_CLIENT_ID="+sp.AppID,
		"AZURE_CLIENT_CERT="+sp.Cert,
		"AZURE_CLIENT_SECRET="+sp.Secret,
	)
	for k, v := range extra {
		e = append(e, k+"="+v)
	}
	return e
}

// prefixWriter tags each child's output line with its component name.
type prefixWriter struct {
	name string
	w    *os.File
}

func (p prefixWriter) Write(b []byte) (int, error) {
	_, _ = p.w.WriteString("[" + p.name + "] ")
	_, _ = p.w.Write(b)
	return len(b), nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
