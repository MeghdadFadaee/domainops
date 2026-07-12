package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/MeghdadFadaee/domainops/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err := cli.Execute(ctx, os.Stdout, os.Stderr, os.Args[1:])
	if err == nil {
		return
	}
	if !cli.IsReportedError(err) {
		fmt.Fprintln(os.Stderr, "domainops:", err)
	}
	var exitErr *cli.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}
	os.Exit(1)
}
