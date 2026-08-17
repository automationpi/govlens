// Command web serves the governance dashboard.
//
//	web -dsn postgres://... -addr :8080 -tenant example
package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/automationpi/govlens/internal/auth"
	"github.com/automationpi/govlens/internal/store"
	"github.com/automationpi/govlens/internal/web"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "Postgres DSN (or DATABASE_URL)")
	addr := flag.String("addr", envOr("ADDR", ":8080"), "listen address")
	tenant := flag.String("tenant", envOr("TENANT", "example"), "tenant to display")
	flag.Parse()
	if *dsn == "" {
		log.Fatal("missing -dsn / DATABASE_URL")
	}

	ctx := context.Background()
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	a, err := auth.NewFromEnv(ctx, s)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := web.New(s, *tenant, a)
	if err != nil {
		log.Fatal(err)
	}
	authMode := "off"
	if a.Enabled {
		authMode = a.Provider.Name()
	}
	log.Printf("govlens listening on %s (tenant=%s, auth=%s)", *addr, *tenant, authMode)
	if err := web.Serve(ctx, *addr, srv); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
