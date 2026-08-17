// Command grantworker is the write-capable worker for the self-service grant
// module. Each cycle it (1) re-probes the grant SP so the readiness gate stays
// fresh, (2) provisions APPROVED grant requests by CREATING role assignments, and
// (3) sweeps expired grants, enqueuing a revoke for the remediator to remove.
//
// It only ever ADDS access (PUT roleAssignments); it holds no delete permission.
// Default is DRY-RUN. With -interval N it loops every N seconds.
//
//	grantworker -execute -interval 3600
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/automationpi/govlens/internal/collect"
	"github.com/automationpi/govlens/internal/store"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "Postgres DSN")
	spTenant := flag.String("sp-tenant", os.Getenv("AZURE_TENANT_ID"), "grant SP tenant id (also the GovLens tenant key)")
	spApp := flag.String("sp-app", os.Getenv("AZURE_CLIENT_ID"), "grant SP app id")
	spCert := flag.String("sp-cert", os.Getenv("AZURE_CLIENT_CERT"), "grant SP certificate (path, inline PEM, or base64)")
	spSecret := flag.String("sp-secret", os.Getenv("AZURE_CLIENT_SECRET"), "grant SP client secret (alternative to -sp-cert)")
	rootScope := flag.String("root-scope", os.Getenv("GRANT_ROOT_SCOPE"), "root scope to probe (default: from grant_sp row)")
	execute := flag.Bool("execute", false, "actually create assignments; default is dry-run")
	interval := flag.Int("interval", 0, "if >0, loop every N seconds instead of running once")
	flag.Parse()
	if *dsn == "" || *spTenant == "" || *spApp == "" || (*spCert == "" && *spSecret == "") {
		log.Fatal("need -dsn, -sp-tenant, -sp-app, and one of -sp-cert / -sp-secret")
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
	tenant := *spTenant

	if *interval <= 0 {
		runCycle(ctx, st, sp, tenant, *rootScope, *execute)
		return
	}
	log.Printf("grantworker scheduled: every %ds, execute=%v", *interval, *execute)
	for {
		runCycle(ctx, st, sp, tenant, *rootScope, *execute)
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

func runCycle(ctx context.Context, st *store.Store, sp *collect.SP, tenant, rootScope string, execute bool) {
	// 1) Re-probe so the readiness gate stays fresh (24h TTL). Fail-closed: if the
	// SP can't be verified this cycle, provision nothing.
	scope := rootScope
	if scope == "" {
		if cfg, _ := st.GrantSP(ctx, tenant); cfg.RootScope != "" {
			scope = cfg.RootScope
		}
	}
	ok, note := collect.ProbeGrantSP(ctx, sp, scope)
	_ = st.MarkGrantSPProbe(ctx, tenant, ok, note)
	if !ok {
		log.Printf("grant SP not verified — skipping provisioning this cycle: %s", note)
	}

	// 2) Provision approved grants.
	if ok {
		reqs, err := st.ListGrantByStatus(ctx, "approved")
		if err != nil {
			log.Printf("list approved grants: %v", err)
		} else {
			mode := "DRY-RUN (no changes)"
			if execute {
				mode = "EXECUTE (will create assignments)"
			}
			log.Printf("grantworker: %s — %d approved grant(s)", mode, len(reqs))
			var granted, skipped, failed int
			for _, r := range reqs {
				label := r.Role + " → " + r.Principal + " @ " + r.Scope
				if !st.IsGrantable(ctx, r.Tenant, r.RoleDefID) {
					log.Printf("  SKIP  #%d %s — role no longer requestable under policy", r.ID, label)
					if execute {
						_ = st.SetRequestStatus(ctx, r.ID, "skipped", "role no longer requestable")
					}
					skipped++
					continue
				}
				if r.PrincipalOid == "" {
					log.Printf("  SKIP  #%d %s — no target principal object id", r.ID, label)
					if execute {
						_ = st.SetRequestStatus(ctx, r.ID, "skipped", "missing target object id")
					}
					skipped++
					continue
				}
				if !execute {
					log.Printf("  WOULD GRANT  #%d %s (expires %s)", r.ID, label, expiryText(r))
					continue
				}
				_ = st.SetRequestStatus(ctx, r.ID, "processing", "")
				ident, err := collect.ProvisionGrant(ctx, sp, r.RoleDefID, r.PrincipalOid, r.PrincipalType, r.Scope)
				if err != nil {
					log.Printf("  FAIL  #%d %s — %v", r.ID, label, err)
					_ = st.SetRequestStatus(ctx, r.ID, "failed", err.Error())
					failed++
					continue
				}
				log.Printf("  GRANTED  #%d %s (expires %s)", r.ID, label, expiryText(r))
				_ = st.SetGrantProvisioned(ctx, r.ID, ident)
				granted++
			}
			if execute {
				log.Printf("provision done: granted=%d skipped=%d failed=%d", granted, skipped, failed)
			}
		}
	}

	// 3) Expiry sweep — enqueue a revoke (for the remediator) for each expired grant.
	expired, err := st.ExpiredGrants(ctx)
	if err != nil {
		log.Printf("expiry sweep: %v", err)
		return
	}
	if len(expired) == 0 {
		return
	}
	log.Printf("expiry sweep: %d grant(s) past expiry", len(expired))
	for _, g := range expired {
		if !execute {
			log.Printf("  WOULD EXPIRE  #%d %s → %s", g.ID, g.Role, g.Principal)
			continue
		}
		if err := st.EnqueueExpiryRevoke(ctx, g); err != nil {
			log.Printf("  expiry enqueue #%d failed: %v", g.ID, err)
			continue
		}
		_ = st.MarkGrantExpired(ctx, g.ID, "expired — revocation queued for remediator")
		log.Printf("  EXPIRED  #%d %s ← %s (revoke queued)", g.ID, g.Role, g.Principal)
	}
}

func expiryText(r store.RevokeRequest) string {
	if r.ExpiresAt.IsZero() {
		return "never"
	}
	return r.ExpiresAt.Format("2006-01-02 15:04")
}
