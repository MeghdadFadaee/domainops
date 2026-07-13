package bootstrap

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	legolog "github.com/go-acme/lego/v5/log"
)

func TestReconcileJobsAfterRecoveryRunsOnlyAfterSuccessfulRecovery(t *testing.T) {
	t.Parallel()
	recoveryFailure := errors.New("journal recovery failed")
	called := false
	err := reconcileJobsAfterRecovery(recoveryFailure, func() error {
		called = true
		return nil
	})
	if !errors.Is(err, recoveryFailure) || called {
		t.Fatalf("failed recovery result = %v, reconcile called=%v", err, called)
	}

	reconcileFailure := errors.New("job reconciliation failed")
	err = reconcileJobsAfterRecovery(nil, func() error {
		called = true
		return reconcileFailure
	})
	if !called || !errors.Is(err, reconcileFailure) {
		t.Fatalf("successful recovery result = %v, reconcile called=%v", err, called)
	}
}

func TestConfigureACMELoggerDoesNotWriteToTerminal(t *testing.T) {
	original := legolog.Default()
	defer legolog.SetDefault(original)
	var output bytes.Buffer
	legolog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	configureACMELogger()
	legolog.Info("dns01: waiting for record propagation.", slog.String("domain", "*.example.com"))
	if output.Len() != 0 {
		t.Fatalf("ACME logger escaped to terminal: %q", output.String())
	}
}
