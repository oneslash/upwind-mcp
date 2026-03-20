package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"upwind-mcp/internal/config"
	"upwind-mcp/internal/mcpserver"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type command struct {
	transport       string
	allowPublicBind bool
	printVersion    bool
}

type usageError struct {
	err error
}

func (e usageError) Error() string {
	return e.err.Error()
}

func (e usageError) Unwrap() error {
	return e.err
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runContext(ctx, args, stdout); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			if !errors.Is(err, flag.ErrHelp) {
				_, _ = fmt.Fprintf(stderr, "%v\n\n", err)
			}
			_, _ = io.WriteString(stderr, usageText())
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 1
		}

		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}

	return 0
}

func runContext(ctx context.Context, args []string, stdout io.Writer) error {
	cmd, err := parseCommand(args)
	if err != nil {
		return err
	}
	if cmd.printVersion {
		_, err := fmt.Fprintln(stdout, versionText())
		return err
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}

	server := mcpserver.New(cfg)
	switch cmd.transport {
	case "stdio":
		return mcpserver.RunStdio(ctx, server)
	case "http":
		return mcpserver.ServeHTTP(ctx, server, cfg, mcpserver.HTTPOptions{
			AllowPublicBind: cmd.allowPublicBind,
		})
	default:
		return fmt.Errorf("unsupported transport %q", cmd.transport)
	}
}

func parseCommand(args []string) (command, error) {
	if len(args) == 0 {
		return command{transport: "stdio"}, nil
	}

	switch args[0] {
	case "help", "-h", "--help":
		return command{}, usageError{err: flag.ErrHelp}
	case "version", "-version", "--version":
		if len(args) != 1 {
			return command{}, usageError{err: fmt.Errorf("unexpected arguments: %s", strings.Join(args[1:], " "))}
		}
		return command{printVersion: true}, nil
	case "serve-http":
		fs := flag.NewFlagSet("serve-http", flag.ContinueOnError)
		fs.SetOutput(io.Discard)

		cmd := command{transport: "http"}
		fs.BoolVar(&cmd.allowPublicBind, "public-bind", false, "allow non-loopback HTTP binds")

		if err := fs.Parse(args[1:]); err != nil {
			return command{}, usageError{err: err}
		}
		if fs.NArg() != 0 {
			return command{}, usageError{err: fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))}
		}

		return cmd, nil
	default:
		return command{}, usageError{err: fmt.Errorf("unknown command %q", args[0])}
	}
}

func versionText() string {
	return fmt.Sprintf("upwind-mcp %s (commit %s, built %s)", version, commit, date)
}

func usageText() string {
	return `Usage:
  upwind-mcp
  upwind-mcp version
  upwind-mcp serve-http [--public-bind]

Commands:
  version       Print build version information
  serve-http    Run the MCP server over Streamable HTTP

Flags:
  --public-bind Allow non-loopback HTTP binds for serve-http
`
}
