package bootstrap

import (
	"errors"
	"testing"
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
