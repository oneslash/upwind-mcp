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

type command struct {
	transport       string
	allowPublicBind bool
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
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runContext(ctx, args); err != nil {
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

func runContext(ctx context.Context, args []string) error {
	cmd, err := parseCommand(args)
	if err != nil {
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

func usageText() string {
	return `Usage:
  upwind-mcp
  upwind-mcp serve-http [--public-bind]

Commands:
  serve-http    Run the MCP server over Streamable HTTP

Flags:
  --public-bind Allow non-loopback HTTP binds for serve-http
`
}
