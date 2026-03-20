package main

import (
	"errors"
	"flag"
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
