package certificates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/identifier"
	"github.com/MeghdadFadaee/domainops/internal/provider"
	"github.com/go-acme/lego/v5/challenge/dns01"
)

type ChallengeRepository interface {
	SaveChallenge(context.Context, domain.ChallengeJournal) error
	ListOpenChallenges(context.Context) ([]domain.ChallengeJournal, error)
	MarkChallengeCleaned(context.Context, string, time.Time) error
}

// ZoneResolver returns the explicit credential and provider zone owning an
// ACME FQDN. It must not silently fall back to another credential.
type ZoneResolver func(context.Context, string) (provider.Auth, string, error)

// CredentialResolver loads the exact provider credential recorded when a
// challenge intent was created. It prevents a later preference change from
// redirecting cleanup through another token.
type CredentialResolver func(context.Context, string) (provider.Auth, error)

type presentedChallenge struct {
	journalID string
	auth      provider.Auth
	zoneID    string
	recordID  string
}

// JournaledDNSProvider adapts DomainOps' provider-neutral DNS solver to lego's
// challenge interface. Every exact record ID is durable before Present returns.
type JournaledDNSProvider struct {
	Solver             provider.DNS01Solver
	Repository         ChallengeRepository
	Resolve            ZoneResolver
	JobID              string
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	OnWriteObserved    func(context.Context, string, string) error
	OnPresented        func(domainName, fqdn string)

	mu        sync.Mutex
	presented map[string]presentedChallenge
}

func NewJournaledDNSProvider(solver provider.DNS01Solver, repository ChallengeRepository, resolve ZoneResolver, jobID string) *JournaledDNSProvider {
	return &JournaledDNSProvider{
		Solver:             solver,
		Repository:         repository,
		Resolve:            resolve,
		JobID:              jobID,
		PropagationTimeout: 2 * time.Minute,
		PollingInterval:    2 * time.Second,
		presented:          make(map[string]presentedChallenge),
	}
}

func (p *JournaledDNSProvider) Present(ctx context.Context, domainName, token, keyAuth string) error {
	if p == nil || p.Solver == nil || p.Repository == nil || p.Resolve == nil {
		return errors.New("DNS-01 provider is not fully configured")
	}
	info := dns01.GetChallengeInfo(ctx, domainName, keyAuth)
	auth, zoneID, err := p.Resolve(ctx, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("resolve DNS-01 zone for %s: %w", info.EffectiveFQDN, err)
	}
	digest := sha256.Sum256([]byte(info.Value))
	journal := domain.ChallengeJournal{
		ID: identifier.New("challenge"), JobID: p.JobID, CredentialID: auth.CredentialID,
		ZoneID: zoneID, FQDN: info.EffectiveFQDN, ValueHash: hex.EncodeToString(digest[:]), CreatedAt: time.Now().UTC(),
	}
	// Persist intent before the provider call so an ambiguous response can be
	// reconciled by owner, job marker, and value hash on the next unlock.
	if err := p.Repository.SaveChallenge(ctx, journal); err != nil {
		return fmt.Errorf("persist DNS-01 challenge intent: %w", err)
	}
	recordID, err := p.Solver.PresentDNS01(ctx, auth, zoneID, info.EffectiveFQDN, info.Value, p.JobID)
	if err != nil {
		return fmt.Errorf("create DNS-01 record %s: %w", info.EffectiveFQDN, err)
	}
	journal.RecordID = recordID
	if err := p.Repository.SaveChallenge(ctx, journal); err != nil {
		cleanupErr := p.Solver.CleanupDNS01(ctx, auth, zoneID, recordID)
		if cleanupErr == nil {
			_ = p.Repository.MarkChallengeCleaned(context.WithoutCancel(ctx), journal.ID, time.Now().UTC())
			return fmt.Errorf("persist DNS-01 record identity: %w", err)
		}
		return errors.Join(fmt.Errorf("persist DNS-01 record identity: %w", err), fmt.Errorf("rollback DNS-01 record %s: %w", recordID, cleanupErr))
	}
	if p.OnWriteObserved != nil {
		_ = p.OnWriteObserved(context.WithoutCancel(ctx), auth.CredentialID, zoneID)
	}

	p.mu.Lock()
	p.presented[challengeKey(domainName, token)] = presentedChallenge{
		journalID: journal.ID,
		auth:      auth,
		zoneID:    zoneID,
		recordID:  recordID,
	}
	p.mu.Unlock()
	if p.OnPresented != nil {
		p.OnPresented(domainName, info.EffectiveFQDN)
	}
	return nil
}

func (p *JournaledDNSProvider) CleanUp(ctx context.Context, domainName, token, _ string) error {
	if p == nil {
		return errors.New("DNS-01 provider is nil")
	}
	key := challengeKey(domainName, token)
	p.mu.Lock()
	presented, ok := p.presented[key]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("DNS-01 record for %s is not present in this process", domainName)
	}
	// lego calls cleanup with the issuance context, which may already be
	// cancelled or expired. Give exact-record cleanup its own bounded window so
	// operator cancellation does not strand a live ACME TXT record.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	if err := p.Solver.CleanupDNS01(cleanupCtx, presented.auth, presented.zoneID, presented.recordID); err != nil {
		return fmt.Errorf("delete DNS-01 record %s: %w", presented.recordID, err)
	}
	cleanedAt := time.Now().UTC()
	if err := p.Repository.MarkChallengeCleaned(cleanupCtx, presented.journalID, cleanedAt); err != nil {
		return fmt.Errorf("mark DNS-01 challenge %s cleaned: %w", presented.journalID, err)
	}
	p.mu.Lock()
	delete(p.presented, key)
	p.mu.Unlock()
	return nil
}

func (p *JournaledDNSProvider) Timeout() (time.Duration, time.Duration) {
	timeout, interval := p.PropagationTimeout, p.PollingInterval
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return timeout, interval
}

// CleanupOpenChallenges recovers exact record IDs left by an interrupted
// process. A challenge is marked clean only after the provider confirms delete.
func CleanupOpenChallenges(ctx context.Context, repository ChallengeRepository, solver provider.DNS01Solver, resolve ZoneResolver, resolveCredential CredentialResolver) error {
	if repository == nil || solver == nil || resolve == nil {
		return errors.New("challenge cleanup is not fully configured")
	}
	challenges, err := repository.ListOpenChallenges(ctx)
	if err != nil {
		return fmt.Errorf("list open DNS-01 challenges: %w", err)
	}
	var cleanupErrors []error
	for _, journal := range challenges {
		if ctx.Err() != nil {
			cleanupErrors = append(cleanupErrors, ctx.Err())
			break
		}
		var auth provider.Auth
		zoneID := journal.ZoneID
		if journal.CredentialID != "" && resolveCredential != nil {
			auth, err = resolveCredential(ctx, journal.CredentialID)
			if err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("load challenge %s credential %s: %w", journal.ID, journal.CredentialID, err))
				continue
			}
		} else {
			var resolvedZoneID string
			auth, resolvedZoneID, err = resolve(ctx, journal.FQDN)
			if err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("resolve challenge %s: %w", journal.ID, err))
				continue
			}
			if zoneID == "" {
				zoneID = resolvedZoneID
			}
			if resolvedZoneID != "" && zoneID != resolvedZoneID {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("challenge %s zone changed from %s to %s", journal.ID, zoneID, resolvedZoneID))
				continue
			}
		}
		if zoneID == "" {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("challenge %s has no provider zone ID", journal.ID))
			continue
		}
		if journal.RecordID == "" {
			reconciler, ok := solver.(provider.DNS01Reconciler)
			if !ok {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("challenge %s has an unresolved create intent and provider cannot reconcile it", journal.ID))
				continue
			}
			recordID, found, reconcileErr := reconciler.ReconcileDNS01(ctx, auth, zoneID, journal.FQDN, journal.ValueHash, journal.JobID)
			if reconcileErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("reconcile challenge %s: %w", journal.ID, reconcileErr))
				continue
			}
			if !found {
				cleanedAt := time.Now().UTC()
				if markErr := repository.MarkChallengeCleaned(ctx, journal.ID, cleanedAt); markErr != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("close absent challenge intent %s: %w", journal.ID, markErr))
				}
				continue
			}
			journal.RecordID = recordID
			if saveErr := repository.SaveChallenge(ctx, journal); saveErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("save reconciled challenge %s: %w", journal.ID, saveErr))
				continue
			}
		}
		if cleanupErr := solver.CleanupDNS01(ctx, auth, zoneID, journal.RecordID); cleanupErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("clean challenge %s record %s: %w", journal.ID, journal.RecordID, cleanupErr))
			continue
		}
		cleanedAt := time.Now().UTC()
		if markErr := repository.MarkChallengeCleaned(ctx, journal.ID, cleanedAt); markErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("mark challenge %s cleaned: %w", journal.ID, markErr))
		}
	}
	return errors.Join(cleanupErrors...)
}

func challengeKey(domainName, token string) string {
	return domainName + "\x00" + token
}
