// Command collect is the lean, PowerShell-free collector. It authenticates as a
// read-only service principal (certificate) and pulls RBAC + Azure Policy
// compliance + Conditional Access straight from ARM/Graph REST into Postgres.
//
//	collect -dsn postgres://... -tenant <label> \
//	        -sp-tenant <tid> -sp-app <appId> -sp-cert <pem> [-collected-at RFC3339]
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
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "Postgres DSN (or DATABASE_URL)")
	label := flag.String("tenant", "", "override tenant key (default: the SP's Entra tenant id)")
	display := flag.String("display", "", "override tenant display name (default: the Entra org name)")
	spTenant := flag.String("sp-tenant", os.Getenv("AZURE_TENANT_ID"), "Entra tenant id of the SP")
	spApp := flag.String("sp-app", os.Getenv("AZURE_CLIENT_ID"), "SP application (client) id")
	spCert := flag.String("sp-cert", os.Getenv("AZURE_CLIENT_CERT"), "SP certificate (path, inline PEM, or base64)")
	spSecret := flag.String("sp-secret", os.Getenv("AZURE_CLIENT_SECRET"), "SP client secret (alternative to -sp-cert)")
	collectedAt := flag.String("collected-at", "", "override run timestamp as RFC3339 (default: now)")
	mg := flag.String("mg", "", "collect only subscriptions under this management group id (default: all readable subs)")
	pseudonymize := flag.Bool("pseudonymize", false, "store hashed principal ids instead of resolving real names (PII-safe)")
	flag.Parse()

	if *dsn == "" || *spTenant == "" || *spApp == "" || (*spCert == "" && *spSecret == "") {
		log.Fatal("need -dsn, -sp-tenant, -sp-app, and one of -sp-cert / -sp-secret")
	}
	at := time.Now().UTC().Truncate(time.Second)
	if *collectedAt != "" {
		t, err := time.Parse(time.RFC3339, *collectedAt)
		if err != nil {
			log.Fatalf("collected-at must be RFC3339: %v", err)
		}
		at = t
	}

	ctx := context.Background()
	sp, err := collect.NewSPFromCred(*spTenant, *spApp, *spCert, *spSecret)
	if err != nil {
		log.Fatal(err)
	}
	c, err := collect.New(ctx, sp)
	if err != nil {
		log.Fatalf("authenticate SP: %v", err)
	}

	rd, err := c.Collect(ctx, collect.Options{
		TenantLabel:  *label,
		Display:      *display,
		CollectedAt:  at,
		MGID:         *mg,
		Pseudonymize: *pseudonymize,
	})
	if err != nil {
		log.Fatalf("collect: %v", err)
	}

	st, err := store.Open(ctx, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	id, err := st.ReplaceRun(ctx, rd)
	if err != nil {
		log.Fatalf("store run: %v", err)
	}
	log.Printf("stored run #%d for %s (%s) at %s", id, rd.TenantDisplay, rd.Tenant, at.Format(time.RFC3339))

	// Reconcile drift: turn any out-of-band role add into a pending review request.
	if n, err := st.ReconcileDrift(ctx, rd.Tenant); err != nil {
		log.Printf("drift reconcile: %v", err)
	} else if n > 0 {
		log.Printf("drift: %d out-of-band change(s) queued for review", n)
	}
}
