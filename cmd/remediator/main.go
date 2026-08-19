// Command remediator is the ONLY component that can revoke access. It picks up
// 'approved' revoke requests, re-validates them, runs a safety gate, and — only
// with -execute and a WRITE-capable service principal — deletes the assignment.
//
// Default is DRY-RUN: it logs what it *would* do and changes nothing. With
// -interval N it loops every N seconds (self-scheduling) instead of exiting.
//
//	remediator -dsn ... -sp-tenant .. -sp-app .. -sp-cert ..                  # dry run once
//	remediator ... -execute                                                   # revoke once
//	remediator ... -execute -interval 3600                                    # revoke hourly
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/automationpi/govlens/internal/collect"
	"github.com/automationpi/govlens/internal/store"
)

type config struct {
	execute    bool
	only       int64
	minGA      int
	breakglass map[string]bool
}

func main() {
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "Postgres DSN")
	spTenant := flag.String("sp-tenant", os.Getenv("AZURE_TENANT_ID"), "SP tenant id")
	spApp := flag.String("sp-app", os.Getenv("AZURE_CLIENT_ID"), "SP app id")
	spCert := flag.String("sp-cert", os.Getenv("AZURE_CLIENT_CERT"), "SP certificate (path, inline PEM, or base64)")
	spSecret := flag.String("sp-secret", os.Getenv("AZURE_CLIENT_SECRET"), "SP client secret (alternative to -sp-cert)")
	execute := flag.Bool("execute", false, "actually delete (requires a write-capable SP); default is dry-run")
	only := flag.Int64("only", 0, "process ONLY this request id (extra safety); 0 = all approved")
	minGA := flag.Int("min-global-admins", 2, "never let a revoke drop Global Admins below this")
	breakglassCSV := flag.String("breakglass", os.Getenv("GOVLENS_BREAKGLASS"), "comma-separated protected principals (never revoked)")
	interval := flag.Int("interval", 0, "if >0, loop every N seconds instead of running once")
	flag.Parse()
	if *dsn == "" || *spTenant == "" || *spApp == "" || (*spCert == "" && *spSecret == "") {
		log.Fatal("need -dsn, -sp-tenant, -sp-app, and one of -sp-cert / -sp-secret")
	}

	cfg := config{execute: *execute, only: *only, minGA: *minGA, breakglass: map[string]bool{}}
	for _, b := range strings.Split(*breakglassCSV, ",") {
		if b = strings.ToLower(strings.TrimSpace(b)); b != "" {
			cfg.breakglass[b] = true
		}
	}

	ctx := context.Background()
	st, err := store.Open(ctx, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	sp, err := collect.NewSPFromCred(*spTenant, *spApp, *spCert, *spSecret)
	if err != nil {
		log.Fatal(err)
	}

	if *interval <= 0 {
		if err := runCycle(ctx, st, sp, cfg); err != nil {
			log.Fatal(err)
		}
		return
	}
	log.Printf("remediator scheduled: every %ds, execute=%v", *interval, cfg.execute)
	for {
		if err := runCycle(ctx, st, sp, cfg); err != nil {
			log.Printf("cycle error: %v", err)
		}
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

// runCycle authenticates fresh (tokens expire), fetches approved requests, and
// processes each through the safety gate.
func runCycle(ctx context.Context, st *store.Store, sp *collect.SP, cfg config) error {
	c, err := collect.New(ctx, sp)
	if err != nil {
		return err
	}
	mode := "DRY-RUN (no changes)"
	if cfg.execute {
		mode = "EXECUTE (will delete)"
	}
	reqs, err := st.ListRevokeByStatus(ctx, "approved")
	if err != nil {
		return err
	}
	if cfg.only > 0 {
		filtered := reqs[:0]
		for _, r := range reqs {
			if r.ID == cfg.only {
				filtered = append(filtered, r)
			}
		}
		reqs = filtered
		log.Printf("remediator: constrained to request #%d", cfg.only)
	}
	log.Printf("remediator: %s — %d approved request(s)", mode, len(reqs))
	if len(reqs) == 0 {
		return nil
	}

	protected, _ := st.ProtectedRoleSet(ctx)
	typePolicies, _ := st.TypePolicies(ctx)

	// The Global-Admin floor guard needs Graph; only fetch it when the batch
	// contains a Global Administrator revoke. -1 = unknown (fail-closed).
	gaCount := -1
	for _, r := range reqs {
		if r.Kind == "entra_role" && r.Role == "Global Administrator" {
			if n, err := c.GlobalAdminCount(ctx); err != nil {
				log.Printf("WARN: cannot read Global Admin count (%v) — GA revokes will be skipped", err)
			} else {
				gaCount = n
				log.Printf("current Global Administrators: %d (floor %d)", gaCount, cfg.minGA)
			}
			break
		}
	}

	var wouldRevoke, revoked, skipped, failed int
	for _, r := range reqs {
		label := r.Role + " ← " + r.Principal

		// --- safety gate ---
		if protected[r.Role] {
			log.Printf("  SKIP  #%d %s — role is protected (non-revocable by admin policy)", r.ID, label)
			skipped++
			if cfg.execute {
				_ = st.SetRequestStatus(ctx, r.ID, "skipped", "role is protected")
			}
			continue
		}
		if typePolicies[r.PrincipalType] == "blocked" {
			log.Printf("  SKIP  #%d %s — principal type %s is blocked by admin policy", r.ID, label, r.PrincipalType)
			skipped++
			if cfg.execute {
				_ = st.SetRequestStatus(ctx, r.ID, "skipped", "principal type blocked")
			}
			continue
		}
		if cfg.breakglass[strings.ToLower(r.Principal)] {
			log.Printf("  SKIP  #%d %s — break-glass protected", r.ID, label)
			skipped++
			if cfg.execute {
				_ = st.SetRequestStatus(ctx, r.ID, "skipped", "break-glass protected")
			}
			continue
		}
		exists, err := c.Exists(ctx, r.Kind, r.TargetIdent)
		if err != nil {
			// A re-validate error (e.g. a 403 from a missing Graph permission) must
			// surface, not silently re-queue every cycle. Mark it failed with the
			// reason so operators can see it; re-request to retry once the cause is fixed.
			log.Printf("  FAIL  #%d %s — re-validate error: %v", r.ID, label, err)
			if cfg.execute {
				_ = st.SetRequestStatus(ctx, r.ID, "failed", "re-validate error: "+err.Error())
			}
			failed++
			continue
		}
		if !exists {
			log.Printf("  SKIP  #%d %s — already gone", r.ID, label)
			skipped++
			if cfg.execute {
				_ = st.SetRequestStatus(ctx, r.ID, "skipped", "already gone")
			}
			continue
		}
		if r.Kind == "entra_role" && r.Role == "Global Administrator" {
			if gaCount < 0 {
				log.Printf("  SKIP  #%d %s — cannot verify Global Admin count (fail-closed)", r.ID, label)
				skipped++
				if cfg.execute {
					_ = st.SetRequestStatus(ctx, r.ID, "skipped", "could not verify Global Admin count")
				}
				continue
			}
			if gaCount <= cfg.minGA {
				log.Printf("  SKIP  #%d %s — would drop Global Admins below floor (%d)", r.ID, label, cfg.minGA)
				skipped++
				if cfg.execute {
					_ = st.SetRequestStatus(ctx, r.ID, "skipped", "would drop below min Global Admins")
				}
				continue
			}
		}

		// --- act ---
		if !cfg.execute {
			log.Printf("  WOULD REVOKE  #%d %s  [%s @ %s]", r.ID, label, r.Kind, r.Scope)
			wouldRevoke++
			continue
		}
		_ = st.SetRequestStatus(ctx, r.ID, "processing", "")
		if err := c.Delete(ctx, r.Kind, r.TargetIdent); err != nil {
			log.Printf("  FAIL  #%d %s — %v", r.ID, label, err)
			_ = st.SetRequestStatus(ctx, r.ID, "failed", err.Error())
			failed++
			continue
		}
		log.Printf("  REVOKED  #%d %s", r.ID, label)
		_ = st.SetRequestStatus(ctx, r.ID, "done", "revoked")
		revoked++
		if r.Role == "Global Administrator" {
			gaCount--
		}
	}

	if cfg.execute {
		log.Printf("done: revoked=%d skipped=%d failed=%d", revoked, skipped, failed)
	} else {
		log.Printf("dry-run summary: would-revoke=%d skipped=%d", wouldRevoke, skipped)
	}
	return nil
}
