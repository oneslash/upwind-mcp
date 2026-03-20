package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestParseCommandDefaultsToStdio(t *testing.T) {
	cmd, err := parseCommand(nil)
	if err != nil {
		t.Fatalf("parseCommand(nil) error = %v", err)
	}
	if cmd.transport != "stdio" {
		t.Fatalf("transport = %q, want stdio", cmd.transport)
	}
	if cmd.allowPublicBind {
		t.Fatal("allowPublicBind = true, want false")
	}
}

func TestParseCommandServeHTTP(t *testing.T) {
	cmd, err := parseCommand([]string{"serve-http", "--public-bind"})
	if err != nil {
		t.Fatalf("parseCommand(serve-http) error = %v", err)
	}
	if cmd.transport != "http" {
		t.Fatalf("transport = %q, want http", cmd.transport)
	}
	if !cmd.allowPublicBind {
		t.Fatal("allowPublicBind = false, want true")
	}
}

func TestParseCommandRejectsUnknownCommand(t *testing.T) {
	_, err := parseCommand([]string{"nope"})
	if err == nil {
		t.Fatal("parseCommand(nope) error = nil, want error")
	}

	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("error %T, want usageError", err)
	}
}

func TestParseCommandHelpIsUsage(t *testing.T) {
	_, err := parseCommand([]string{"--help"})
	if err == nil {
		t.Fatal("parseCommand(--help) error = nil, want error")
	}
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp", err)
	}
}

func TestParseCommandRejectsUnexpectedArgs(t *testing.T) {
	_, err := parseCommand([]string{"serve-http", "extra"})
	if err == nil {
		t.Fatal("parseCommand(serve-http extra) error = nil, want error")
	}

	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("error %T, want usageError", err)
	}
}

func TestParseCommandVersion(t *testing.T) {
	cmd, err := parseCommand([]string{"version"})
	if err != nil {
		t.Fatalf("parseCommand(version) error = %v", err)
	}
	if !cmd.printVersion {
		t.Fatal("printVersion = false, want true")
	}
}

func TestRunVersionDoesNotRequireConfig(t *testing.T) {
	t.Setenv("UPWIND_ORGANIZATION_ID", "")
	t.Setenv("UPWIND_CLIENT_ID", "")
	t.Setenv("UPWIND_CLIENT_SECRET", "")

	origVersion, origCommit, origDate := version, commit, date
	version, commit, date = "v1.2.3", "abcdef0", "2026-03-20T12:00:00Z"
	t.Cleanup(func() {
		version, commit, date = origVersion, origCommit, origDate
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(version) exit code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	got := strings.TrimSpace(stdout.String())
	want := "upwind-mcp v1.2.3 (commit abcdef0, built 2026-03-20T12:00:00Z)"
	if got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}
