package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/app"
	"github.com/MeghdadFadaee/domainops/internal/certificates"
	"github.com/MeghdadFadaee/domainops/internal/config"
	"github.com/MeghdadFadaee/domainops/internal/health"
	"github.com/MeghdadFadaee/domainops/internal/lockfile"
	cloudflareprovider "github.com/MeghdadFadaee/domainops/internal/providers/cloudflare"
	"github.com/MeghdadFadaee/domainops/internal/secrets"
	sqlitestore "github.com/MeghdadFadaee/domainops/internal/store/sqlite"
)

type Options struct {
	DataDir   string
	NoKeyring bool
}

type Runtime struct {
	Paths        config.Paths
	Repository   *sqlitestore.Repository
	Vault        *secrets.Vault
	Application  *app.Service
	Certificates *app.CertificateService
	Health       *health.Checker
	Cloudflare   *cloudflareprovider.Client
	lock         *lockfile.Lock
}

func Open(ctx context.Context, options Options) (*Runtime, error) {
	paths, err := config.Resolve(options.DataDir)
	if err != nil {
		return nil, err
	}
	if err := paths.Ensure(); err != nil {
		return nil, err
	}
	lock, err := lockfile.Acquire(filepath.Join(paths.DataDir, "domainops.lock"))
	if err != nil {
		return nil, err
	}
	fail := func(openErr error) (*Runtime, error) {
		_ = lock.Close()
		return nil, openErr
	}

	repository, err := sqlitestore.New(paths.Database)
	if err != nil {
		return fail(err)
	}
	if err := repository.Migrate(ctx); err != nil {
		_ = repository.Close()
		return fail(err)
	}

	var vault *secrets.Vault
	if options.NoKeyring {
		vault, err = secrets.New(paths.Vault, "", "")
	} else {
		vault, err = secrets.NewDefault(paths.Vault)
	}
	if err != nil {
		_ = repository.Close()
		return fail(err)
	}

	cloudflareClient := cloudflareprovider.New()
	application := app.New(repository, vault)
	application.RegisterProvider("cloudflare", cloudflareClient)

	httpClient := &http.Client{Timeout: 45 * time.Second}
	engine := certificates.NewEngine(repository, vault, application, application.ResolveDNS01,
		certificates.WithACMEHTTPClient(httpClient, "DomainOps/1"),
		certificates.WithPreflight(application.CertificatePreflight),
		certificates.WithDNSWriteObserver(func(observeCtx context.Context, credentialID, providerZoneID string) error {
			return application.ObserveCredentialZoneCapability(observeCtx, credentialID, providerZoneID, "dns:write")
		}))
	certificateService := app.NewCertificateService(repository, vault, engine, paths.Certificates)
	application.SetCertificateService(certificateService)
	checker := &health.Checker{
		Repository:          repository,
		Prober:              health.NewProber(),
		ExpectedFingerprint: certificateService.ExpectedFingerprint,
		Concurrency:         8,
	}
	application.SetHealthCheck(checker.RunOnce)
	application.SetUnlockHook(func(unlockCtx context.Context) error {
		cleanupCtx, cancel := context.WithTimeout(unlockCtx, 10*time.Minute)
		defer cancel()
		recoveryErr := errors.Join(
			certificates.RecoverACMEAccountCommitIntents(cleanupCtx, repository, vault),
			certificates.RecoverCertificateCommitIntents(cleanupCtx, repository, vault, paths.Certificates),
			certificates.CleanupOpenChallenges(cleanupCtx, repository, application, application.ResolveDNS01, application.ResolveCredential),
			certificateService.RepairManagedCurrentLinks(cleanupCtx),
		)
		return reconcileJobsAfterRecovery(recoveryErr, func() error {
			return application.ReconcileInterruptedJobs(cleanupCtx)
		})
	})
	if !vault.Locked() {
		// Keyring auto-unlock happens while the vault is constructed, before the
		// recovery hook exists. Re-entering UnlockVault is a no-op for the vault
		// but guarantees crash-left DNS-01 records are retried on this path too.
		// Match the unlock hook's recovery budget. A large journal can require
		// many bounded provider calls, especially after an extended outage; a
		// shorter parent deadline would silently reduce the ten-minute hook to
		// thirty seconds and leave an otherwise healthy auto-unlocked runtime
		// recovery-blocked.
		recoveryCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		_ = application.UnlockVault(recoveryCtx, nil)
		cancel()
	}

	return &Runtime{
		Paths: paths, Repository: repository, Vault: vault, Application: application,
		Certificates: certificateService, Health: checker, Cloudflare: cloudflareClient, lock: lock,
	}, nil
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.Vault != nil {
		r.Vault.Lock()
	}
	var errs []error
	if r.Repository != nil {
		errs = append(errs, r.Repository.Close())
	}
	if r.lock != nil {
		errs = append(errs, r.lock.Close())
	}
	return errors.Join(errs...)
}

func (r *Runtime) Recover(ctx context.Context) error {
	if r == nil || r.Vault == nil || r.Vault.Locked() {
		return fmt.Errorf("vault must be unlocked before recovery")
	}
	recoveryErr := errors.Join(
		certificates.RecoverACMEAccountCommitIntents(ctx, r.Repository, r.Vault),
		certificates.RecoverCertificateCommitIntents(ctx, r.Repository, r.Vault, r.Paths.Certificates),
		certificates.CleanupOpenChallenges(ctx, r.Repository, r.Application, r.Application.ResolveDNS01, r.Application.ResolveCredential),
		r.Certificates.RepairManagedCurrentLinks(ctx),
	)
	return reconcileJobsAfterRecovery(recoveryErr, func() error {
		return r.Application.ReconcileInterruptedJobs(ctx)
	})
}

func reconcileJobsAfterRecovery(recoveryErr error, reconcile func() error) error {
	if recoveryErr != nil {
		return recoveryErr
	}
	if reconcile == nil {
		return errors.New("interrupted-job reconciliation is not configured")
	}
	return reconcile()
}
