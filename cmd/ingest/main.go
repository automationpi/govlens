// Command ingest loads one or more run directories into Postgres.
//
//	ingest -dsn postgres://... path/to/run [path/to/another-run ...]
//
// With -all, every immediate subdirectory of the given path is treated as a run
// (handy for loading the whole fixtures/ tree at once).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/automationpi/govlens/internal/ingest"
	"github.com/automationpi/govlens/internal/store"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "Postgres DSN (or DATABASE_URL)")
	all := flag.Bool("all", false, "treat each subdirectory of the first arg as a run")
	native := flag.Bool("native", false, "discover raw collector output (AzGovViz/Maester/EntraExporter) instead of the normalized contract")
	specPath := flag.String("spec", "", "optional JSON spec overriding native discovery patterns")
	tenant := flag.String("tenant", "", "override tenant (native mode)")
	collectedAt := flag.String("collected-at", "", "override collected_at as RFC3339 (native mode)")
	flag.Parse()
	if *dsn == "" || flag.NArg() == 0 {
		log.Fatal("usage: ingest -dsn <dsn> [-all] <run-dir>...  |  ingest -dsn <dsn> -native [-spec s.json] [-tenant t] [-collected-at ts] <raw-dir>...")
	}

	ctx := context.Background()
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	if *native {
		runNative(ctx, s, *specPath, *tenant, *collectedAt, collectDirs(*all, flag.Args()))
		return
	}

	dirs := collectDirs(*all, flag.Args())
	for _, d := range dirs {
		id, err := ingest.Run(ctx, s, d)
		if err != nil {
			log.Fatalf("ingest %s: %v", d, err)
		}
		log.Printf("ingested %s as run #%d", d, id)
	}
	log.Printf("done: %d run(s)", len(dirs))
}

func runNative(ctx context.Context, s *store.Store, specPath, tenant, collectedAt string, dirs []string) {
	spec, err := ingest.LoadSpec(specPath)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	var at time.Time
	if collectedAt != "" {
		if at, err = time.Parse(time.RFC3339, collectedAt); err != nil {
			log.Fatalf("collected-at must be RFC3339: %v", err)
		}
	}
	for _, d := range dirs {
		id, err := ingest.RunNative(ctx, s, d, spec, tenant, at)
		if err != nil {
			log.Fatalf("ingest-native %s: %v", d, err)
		}
		log.Printf("ingested raw %s as run #%d", d, id)
	}
	log.Printf("done: %d run(s)", len(dirs))
}

func collectDirs(all bool, args []string) []string {
	if !all {
		return args
	}
	entries, err := os.ReadDir(args[0])
	if err != nil {
		log.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(args[0], e.Name()))
		}
	}
	sort.Strings(dirs)
	return dirs
}
