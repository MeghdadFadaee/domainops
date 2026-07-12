package certificates

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/lego"
)

const maxIssuanceConcurrency = 3

type EngineRepository interface {
	AccountRepository
	ChallengeRepository
}

type CertificateBackend interface {
	Obtain(context.Context, certificate.ObtainRequest) (*certificate.Resource, error)
	RevokeWithReason(context.Context, []byte, *uint) error
	GetRenewalInfo(context.Context, *x509.Certificate) (*certificate.RenewalInfo, error)
}

type BackendFactory interface {
	New(context.Context, AccountMaterial, challenge.Provider) (CertificateBackend, error)
}

type PreflightHook func(context.Context, Plan) error

type Engine struct {
	accounts      *AccountService
	repository    EngineRepository
	solver        provider.DNS01Solver
	resolve       ZoneResolver
	factory       BackendFactory
	preflights    []PreflightHook
	writeObserver func(context.Context, string, string) error
	concurrency   int
}

type EngineOption func(*Engine)

func WithBackendFactory(factory BackendFactory) EngineOption {
	return func(engine *Engine) {
		if factory != nil {
			engine.factory = factory
		}
	}
}

func WithPreflight(hook PreflightHook) EngineOption {
	return func(engine *Engine) {
		if hook != nil {
			engine.preflights = append(engine.preflights, hook)
		}
	}
}

func WithDNSWriteObserver(observer func(context.Context, string, string) error) EngineOption {
	return func(engine *Engine) {
		engine.writeObserver = observer
	}
}

func WithIssuanceConcurrency(concurrency int) EngineOption {
	return func(engine *Engine) {
		if concurrency > 0 {
			engine.concurrency = min(concurrency, maxIssuanceConcurrency)
		}
	}
}

func WithACMEHTTPClient(client *http.Client, userAgent string) EngineOption {
	return func(engine *Engine) {
		engine.accounts.HTTPClient = client
		engine.accounts.UserAgent = userAgent
		engine.factory = &legoBackendFactory{HTTPClient: client, UserAgent: userAgent}
	}
}

func NewEngine(repository EngineRepository, secrets SecretStore, solver provider.DNS01Solver, resolve ZoneResolver, options ...EngineOption) *Engine {
	engine := &Engine{
		accounts:    &AccountService{Repository: repository, Secrets: secrets},
		repository:  repository,
		solver:      solver,
		resolve:     resolve,
		factory:     &legoBackendFactory{},
		concurrency: maxIssuanceConcurrency,
	}
	for _, option := range options {
		option(engine)
	}
	return engine
}

func (e *Engine) Accounts() *AccountService { return e.accounts }

type IssueRequest struct {
	JobID             string `json:"job_id"`
	Environment       string `json:"environment"`
	Plan              Plan   `json:"plan"`
	ConfirmProduction bool   `json:"confirm_production"`
	ReplacesCertID    string `json:"-"`
}

type IssueResult struct {
	Plan          Plan          `json:"plan"`
	Environment   string        `json:"environment"`
	Artifact      Artifact      `json:"-"`
	RenewalWindow RenewalWindow `json:"renewal_window"`
}

func (e *Engine) Issue(ctx context.Context, request IssueRequest) (IssueResult, error) {
	if e == nil || e.repository == nil || e.solver == nil || e.resolve == nil || e.factory == nil {
		return IssueResult{}, errors.New("certificate engine is not fully configured")
	}
	if err := ValidatePlan(request.Plan); err != nil {
		return IssueResult{}, err
	}
	if _, err := DirectoryForEnvironment(request.Environment); err != nil {
		return IssueResult{}, err
	}
	if request.Environment == EnvironmentProduction && !request.ConfirmProduction {
		return IssueResult{}, errors.New("production issuance requires explicit confirmation")
	}
	for _, preflight := range e.preflights {
		if err := preflight(ctx, request.Plan); err != nil {
			return IssueResult{}, fmt.Errorf("certificate preflight: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return IssueResult{}, err
	}

	account, err := e.accounts.Load(ctx, request.Environment)
	if err != nil {
		return IssueResult{}, err
	}
	dnsProvider := NewJournaledDNSProvider(e.solver, e.repository, e.resolve, request.JobID)
	dnsProvider.OnWriteObserved = e.writeObserver
	backend, err := e.factory.New(ctx, account, dnsProvider)
	if err != nil {
		return IssueResult{}, fmt.Errorf("create ACME backend: %w", err)
	}
	privateKey, err := GeneratePrivateKey(request.Plan.KeyAlgorithm)
	if err != nil {
		return IssueResult{}, err
	}
	resource, err := backend.Obtain(ctx, certificate.ObtainRequest{
		Domains:                        slices.Clone(request.Plan.Identifiers),
		PrivateKey:                     privateKey,
		KeyType:                        certcrypto.KeyType(request.Plan.KeyAlgorithm),
		Bundle:                         false,
		EnableCommonName:               true,
		Profile:                        request.Plan.Profile,
		ReplacesCertID:                 request.ReplacesCertID,
		AlwaysDeactivateAuthorizations: true,
	})
	if err != nil {
		return IssueResult{}, fmt.Errorf("obtain certificate for %s: %w", request.Plan.Name, err)
	}
	artifact, err := artifactFromResource(resource, privateKey, request.Plan.Identifiers)
	if err != nil {
		return IssueResult{}, fmt.Errorf("validate ACME result: %w", err)
	}
	leaf, _, _, _, err := ParseCertificatePEM(artifact.CertificatePEM)
	if err != nil {
		return IssueResult{}, fmt.Errorf("parse issued certificate for renewal scheduling: %w", err)
	}
	renewalWindow := fallbackRenewalWindow(leaf)
	if ariWindow, ariErr := queryRenewalWindow(ctx, backend, leaf); ariErr == nil {
		renewalWindow = ariWindow
	}
	return IssueResult{
		Plan:          request.Plan,
		Environment:   request.Environment,
		Artifact:      artifact,
		RenewalWindow: renewalWindow,
	}, nil
}

type BatchResult struct {
	Request IssueRequest `json:"request"`
	Result  IssueResult  `json:"-"`
	Error   error        `json:"-"`
}

// IssueBatch preserves input order and caps active orders at three even when a
// caller asks for more. Each plan remains an independent certificate order.
func (e *Engine) IssueBatch(ctx context.Context, requests []IssueRequest) []BatchResult {
	results := make([]BatchResult, len(requests))
	for index := range requests {
		results[index].Request = requests[index]
	}
	if len(requests) == 0 {
		return results
	}
	concurrency := maxIssuanceConcurrency
	if e != nil && e.concurrency > 0 {
		concurrency = min(e.concurrency, maxIssuanceConcurrency)
	}
	concurrency = min(concurrency, len(requests))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				results[index].Result, results[index].Error = e.Issue(ctx, requests[index])
			}
		}()
	}
	next := 0
send:
	for ; next < len(requests); next++ {
		select {
		case jobs <- next:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	workers.Wait()
	for ; next < len(requests); next++ {
		results[next].Error = ctx.Err()
	}
	return results
}

type RenewRequest struct {
	IssueRequest
	PreviousCertificatePEM []byte `json:"-"`
}

// Renew obtains a replacement with a fresh private key. It deliberately does
// not reuse the prior key, even when the CA would permit it.
func (e *Engine) Renew(ctx context.Context, request RenewRequest) (IssueResult, error) {
	previousCertificate, _, _, previous, err := ParseCertificatePEM(request.PreviousCertificatePEM)
	if err != nil {
		return IssueResult{}, fmt.Errorf("parse previous certificate: %w", err)
	}
	expected := slices.Clone(request.Plan.Identifiers)
	actual := slices.Clone(previous.Identifiers)
	slices.Sort(expected)
	slices.Sort(actual)
	if !slices.Equal(expected, actual) {
		return IssueResult{}, errors.New("renewal plan identifiers differ from the previous certificate")
	}
	certID, err := api.MakeARICertID(previousCertificate)
	if err != nil {
		return IssueResult{}, fmt.Errorf("build ARI replacement certificate ID: %w", err)
	}
	request.IssueRequest.ReplacesCertID = certID
	return e.Issue(ctx, request.IssueRequest)
}

type RevokeRequest struct {
	Environment       string
	Lineage           domain.CertificateLineage
	CertificatePEM    []byte
	Reason            *uint
	ConfirmRevocation bool
}

func (e *Engine) Revoke(ctx context.Context, request RevokeRequest) error {
	if !request.ConfirmRevocation {
		return errors.New("certificate revocation requires explicit confirmation")
	}
	if request.Lineage.Source != domain.CertificateManaged {
		return errors.New("only certificates managed by DomainOps can be revoked")
	}
	if _, _, _, _, err := ParseCertificatePEM(request.CertificatePEM); err != nil {
		return err
	}
	account, err := e.accounts.Load(ctx, request.Environment)
	if err != nil {
		return err
	}
	backend, err := e.factory.New(ctx, account, nil)
	if err != nil {
		return fmt.Errorf("create ACME backend: %w", err)
	}
	if err := backend.RevokeWithReason(ctx, request.CertificatePEM, request.Reason); err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	return nil
}

// IsAlreadyRevoked reports the standardized ACME alreadyRevoked response. It
// lets a durable local revocation intent converge after the CA succeeded but
// the prior local state update failed.
func IsAlreadyRevoked(err error) bool {
	var problem *acme.ProblemDetails
	return errors.As(err, &problem) && problem.Type == acme.AlreadyRevokedErrorType
}

type RenewalWindow struct {
	Start          time.Time     `json:"start"`
	End            time.Time     `json:"end"`
	ARI            bool          `json:"ari"`
	ExplanationURL string        `json:"explanation_url,omitempty"`
	RetryAfter     time.Duration `json:"retry_after,omitempty"`
}

func (e *Engine) RenewalInfo(ctx context.Context, environment string, certificatePEM []byte) (RenewalWindow, error) {
	leaf, _, _, _, err := ParseCertificatePEM(certificatePEM)
	if err != nil {
		return RenewalWindow{}, err
	}
	account, err := e.accounts.Load(ctx, environment)
	if err != nil {
		return RenewalWindow{}, err
	}
	backend, err := e.factory.New(ctx, account, nil)
	if err != nil {
		return RenewalWindow{}, fmt.Errorf("create ACME backend: %w", err)
	}
	window, err := queryRenewalWindow(ctx, backend, leaf)
	if err != nil {
		return fallbackRenewalWindow(leaf), fmt.Errorf("query ACME renewal information: %w", err)
	}
	return window, nil
}

func fallbackRenewalWindow(certificate *x509.Certificate) RenewalWindow {
	return fallbackRenewalWindowForValidity(certificate.NotBefore, certificate.NotAfter)
}

func fallbackRenewalWindowForValidity(notBefore, notAfter time.Time) RenewalWindow {
	notBefore = notBefore.UTC()
	notAfter = notAfter.UTC()
	if notBefore.IsZero() || !notAfter.After(notBefore) {
		return RenewalWindow{}
	}
	lifetime := notAfter.Sub(notBefore)
	window := RenewalWindow{
		Start: notBefore.Add(lifetime * 2 / 3).UTC(),
		End:   notBefore.Add(lifetime * 5 / 6).UTC(),
		ARI:   false,
	}
	if !validRenewalWindow(window, notBefore, notAfter) {
		return RenewalWindow{}
	}
	return window
}

func queryRenewalWindow(ctx context.Context, backend CertificateBackend, certificate *x509.Certificate) (RenewalWindow, error) {
	info, err := backend.GetRenewalInfo(ctx, certificate)
	if err != nil {
		return RenewalWindow{}, err
	}
	if info == nil || info.ExtendedRenewalInfo == nil {
		return RenewalWindow{}, errors.New("ACME server returned no renewal information")
	}
	window := normalizeRenewalWindow(RenewalWindow{
		Start:          info.SuggestedWindow.Start,
		End:            info.SuggestedWindow.End,
		ARI:            true,
		ExplanationURL: info.ExplanationURL,
		RetryAfter:     info.RetryAfter,
	})
	if !validRenewalWindow(window, certificate.NotBefore, certificate.NotAfter) {
		return RenewalWindow{}, errors.New("ACME server returned an invalid renewal window")
	}
	return window, nil
}

func normalizeRenewalWindow(window RenewalWindow) RenewalWindow {
	window.Start = window.Start.UTC()
	window.End = window.End.UTC()
	return window
}

func validRenewalWindow(window RenewalWindow, notBefore, notAfter time.Time) bool {
	window = normalizeRenewalWindow(window)
	notBefore = notBefore.UTC()
	notAfter = notAfter.UTC()
	if window.Start.IsZero() || window.End.IsZero() || !window.End.After(window.Start) {
		return false
	}
	if notBefore.IsZero() || !notAfter.After(notBefore) {
		return false
	}
	if window.Start.Before(notBefore) || window.End.After(notAfter) {
		return false
	}
	return window.RetryAfter >= 0
}

func artifactFromResource(resource *certificate.Resource, privateKey crypto.Signer, expected []string) (Artifact, error) {
	if resource == nil {
		return Artifact{}, errors.New("ACME server returned no certificate resource")
	}
	_, leafPEM, embeddedChain, metadata, err := ParseCertificatePEM(resource.Certificate)
	if err != nil {
		return Artifact{}, err
	}
	chain := append(slices.Clone(embeddedChain), resource.IssuerCertificate...)
	keyPEM, err := MarshalPrivateKeyPKCS8(privateKey)
	if err != nil {
		return Artifact{}, err
	}
	artifact := Artifact{
		CertificatePEM: leafPEM,
		ChainPEM:       chain,
		PrivateKeyPEM:  keyPEM,
		Metadata:       metadata,
	}
	if _, err := ValidateArtifact(artifact, expected); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

type legoBackendFactory struct {
	HTTPClient *http.Client
	UserAgent  string
}

func (f *legoBackendFactory) New(_ context.Context, material AccountMaterial, dnsProvider challenge.Provider) (CertificateBackend, error) {
	user := &legoUser{
		email:        material.Account.Email,
		privateKey:   material.PrivateKey,
		registration: material.Registration,
	}
	config := lego.NewConfig(user)
	config.CADirURL = material.Account.DirectoryURL
	if f.HTTPClient != nil {
		config.HTTPClient = f.HTTPClient
	}
	if f.UserAgent != "" {
		config.UserAgent = f.UserAgent
	}
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	if dnsProvider != nil {
		if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
			return nil, fmt.Errorf("configure DNS-01 provider: %w", err)
		}
	}
	return legoCertificateBackend{certifier: client.Certificate}, nil
}

type legoCertificateBackend struct {
	certifier *certificate.Certifier
}

func (b legoCertificateBackend) Obtain(ctx context.Context, request certificate.ObtainRequest) (*certificate.Resource, error) {
	return b.certifier.Obtain(ctx, request)
}

func (b legoCertificateBackend) RevokeWithReason(ctx context.Context, certificatePEM []byte, reason *uint) error {
	return b.certifier.RevokeWithReason(ctx, certificatePEM, reason)
}

func (b legoCertificateBackend) GetRenewalInfo(ctx context.Context, certificate *x509.Certificate) (*certificate.RenewalInfo, error) {
	return b.certifier.GetRenewalInfo(ctx, certificate)
}
