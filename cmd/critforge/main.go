// Command critforge is the CritForge M0 control binary.
//
// CritForge is an AUTHORIZED-USE-ONLY, black-box pentest orchestration
// platform. M0 is the skeleton & compliance shell: it contains NO scanning,
// enumeration, network, or exploit capability. The only runnable command is
// "health", which validates the authorization spine and writes one audit entry.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/critforge/critforge/internal/audit"
	"github.com/critforge/critforge/internal/scopepolicy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "health":
		os.Exit(health(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`critforge (M0 skeleton) — authorized-use-only

Usage:
  critforge health [--scope path]   Validate the spine and write one audit entry.

M0 contains no offensive capability. Scanning/exploit modules are stubs only.`)
}

func health(args []string) int {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	scopePath := fs.String("scope", "scope.yaml", "path to scope file")
	actor := fs.String("actor", "system", "actor performing the health check")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	sink := audit.Default()
	scope, err := scopepolicy.Load(*scopePath)
	if err != nil {
		// Record the failed authorization check, then fail closed.
		_ = audit.Record(sink, *actor, "health.scope_check_failed", *scopePath, err.Error())
		if errors.Is(err, scopepolicy.ErrEmptyScope) {
			fmt.Fprintln(os.Stderr, "authorization gate: refusing to run with empty scope")
		} else {
			fmt.Fprintf(os.Stderr, "health: %v\n", err)
		}
		return 1
	}

	if err := audit.Record(sink, *actor, "health.ok", scope.Project, "M0 spine healthy"); err != nil {
		fmt.Fprintf(os.Stderr, "health: audit write failed: %v\n", err)
		return 1
	}
	fmt.Printf("OK  project=%q targets=%d gate=%s\n", scope.Project, len(scope.Allowlist), scope.SeverityGate)
	return 0
}
