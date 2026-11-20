// Command demo-seed writes clearly labelled sample data (organization "Acme Demo", .test
// hosts, documentation-range addresses, six weekly scans) into the VulWall database, for
// screenshots and demos. Every document it inserts carries demo: true.
//
// Usage:
//
//	demo-seed           seed; refuses when the organization has its own assets or findings
//	demo-seed --force   seed anyway (the sample data is added next to the real data)
//	demo-seed --reset   delete the sample data and restore the organization's name and schedule
//
// It reads MONGO_URI (default mongodb://localhost:27017) and MONGO_DB (default vulwall).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/demoseed"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	force := flag.Bool("force", false, "seed even when the organization has its own assets or findings")
	reset := flag.Bool("reset", false, "delete the sample data (demo: true) instead of seeding")
	flag.Parse()
	if err := run(*force, *reset); err != nil {
		fmt.Fprintln(os.Stderr, "demo-seed:", err)
		os.Exit(1)
	}
}

func run(force, reset bool) error {
	uri := envOr(config.EnvMongoURI, "mongodb://localhost:27017")
	dbName := envOr(config.EnvMongoDB, "vulwall")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return fmt.Errorf("connect to MongoDB: %w", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	db := client.Database(dbName)

	if reset {
		res, err := demoseed.Reset(ctx, db)
		if err != nil {
			return err
		}
		fmt.Printf("Removed the sample data from %q:", dbName)
		for coll, n := range res.Deleted {
			if n > 0 {
				fmt.Printf(" %s %d,", coll, n)
			}
		}
		fmt.Printf(" organizations restored %d.\n", res.OrgsRestored)
		return nil
	}

	ds, err := demoseed.Apply(ctx, db, demoseed.Options{
		Force: force, Now: time.Now(), Version: envOr("VULWALL_VERSION", "v0.1.0"),
	})
	if err != nil {
		return err
	}
	fmt.Printf("Seeded sample data into %q for %s: %d assets, %d discoveries, %d findings, %d scans.\n",
		dbName, demoseed.CompanyName, len(ds.Assets), len(ds.Discoveries), len(ds.Findings), len(ds.Scans))
	fmt.Println("Remove it again with --reset.")
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
