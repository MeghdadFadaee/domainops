package certificates

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/identifier"
	"github.com/MeghdadFadaee/domainops/internal/store"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

type AccountRepository interface {
	SaveACMEAccount(context.Context, domain.ACMEAccount) error
	CommitACMEAccount(context.Context, domain.ACMEAccount) error
	GetACMEAccountByEnvironment(context.Context, string) (domain.ACMEAccount, error)
	SaveACMEAccountCommitIntent(context.Context, domain.ACMEAccountCommitIntent) error
	ListACMEAccountCommitIntents(context.Context) ([]domain.ACMEAccountCommitIntent, error)
	DeleteACMEAccountCommitIntent(context.Context, string) error
}

type SecretStore interface {
	Put(context.Context, string, []byte) (string, error)
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

type AccountMaterial struct {
	Account      domain.ACMEAccount
	PrivateKey   crypto.Signer
	Registration *acme.ExtendedAccount
}

type RegisterAccountRequest struct {
	Environment          string
	Email                string
	TermsOfServiceAgreed bool
	DirectoryURL         string
	AllowCustomDirectory bool
}

type AccountService struct {
	Repository AccountRepository
	Secrets    SecretStore
	HTTPClient *http.Client
	UserAgent  string
}

func DirectoryForEnvironment(environment string) (string, error) {
	switch environment {
	case EnvironmentStaging:
		return lego.DirectoryURLLetsEncryptStaging, nil
	case EnvironmentProduction:
		return lego.DirectoryURLLetsEncrypt, nil
	default:
		return "", fmt.Errorf("unknown ACME environment %q", environment)
	}
}

// Register creates one independent ACME account per environment. The account
// key goes directly to the encrypted secret store and never to process-global
// environment variables or the metadata database.
func (s *AccountService) Register(ctx context.Context, request RegisterAccountRequest) (domain.ACMEAccount, error) {
	if s == nil || s.Repository == nil || s.Secrets == nil {
		return domain.ACMEAccount{}, errors.New("ACME account service is not fully configured")
	}
	if !request.TermsOfServiceAgreed {
		return domain.ACMEAccount{}, errors.New("ACME terms of service must be explicitly accepted")
	}
	address, err := mail.ParseAddress(strings.TrimSpace(request.Email))
	if err != nil || address.Address != strings.TrimSpace(request.Email) {
		return domain.ACMEAccount{}, errors.New("a valid ACME contact email is required")
	}
	directoryURL, err := DirectoryForEnvironment(request.Environment)
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	if request.DirectoryURL != "" {
		if !request.AllowCustomDirectory {
			return domain.ACMEAccount{}, errors.New("a custom ACME directory requires explicit opt-in")
		}
		directoryURL = request.DirectoryURL
	}

	privateKey, err := GeneratePrivateKey(domain.KeyECDSAP256)
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	keyPEM, err := MarshalPrivateKeyPKCS8(privateKey)
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	accountID := identifier.New("acmeacct")
	now := time.Now().UTC()
	intent := domain.ACMEAccountCommitIntent{
		AccountID: accountID, SecretRef: "acme-account/" + accountID, CreatedAt: now,
	}
	if err := s.Repository.SaveACMEAccountCommitIntent(ctx, intent); err != nil {
		return domain.ACMEAccount{}, fmt.Errorf("journal ACME account key: %w", err)
	}
	secretRef, err := s.Secrets.Put(ctx, intent.SecretRef, keyPEM)
	if err != nil {
		if secretRef != "" && secretRef != intent.SecretRef {
			err = errors.Join(err, fmt.Errorf("secret store returned unexpected reference %q", secretRef))
		}
		cleanupErr := cleanupACMEAccountCommitIntent(context.WithoutCancel(ctx), s.Repository, s.Secrets, intent)
		return domain.ACMEAccount{}, errors.Join(fmt.Errorf("store ACME account key: %w", err), cleanupErr)
	}
	if secretRef != intent.SecretRef {
		return domain.ACMEAccount{}, errors.Join(
			errors.New("secret store returned an unexpected ACME account key reference"),
			cleanupACMEAccountCommitIntent(context.WithoutCancel(ctx), s.Repository, s.Secrets, intent),
		)
	}
	failAfterKey := func(operationErr error) (domain.ACMEAccount, error) {
		cleanupErr := cleanupACMEAccountCommitIntent(context.WithoutCancel(ctx), s.Repository, s.Secrets, intent)
		return domain.ACMEAccount{}, errors.Join(operationErr, cleanupErr)
	}
	user := &legoUser{email: address.Address, privateKey: privateKey}
	config := lego.NewConfig(user)
	config.CADirURL = directoryURL
	if s.HTTPClient != nil {
		config.HTTPClient = s.HTTPClient
	}
	if s.UserAgent != "" {
		config.UserAgent = s.UserAgent
	}
	client, err := lego.NewClient(config)
	if err != nil {
		return failAfterKey(fmt.Errorf("create ACME client: %w", err))
	}
	registrationResource, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return failAfterKey(fmt.Errorf("register ACME account: %w", err))
	}
	registrationJSON, err := json.Marshal(registrationResource)
	if err != nil {
		return failAfterKey(fmt.Errorf("encode ACME registration: %w", err))
	}
	account := domain.ACMEAccount{
		ID:           accountID,
		Environment:  request.Environment,
		DirectoryURL: directoryURL,
		Email:        address.Address,
		Registration: string(registrationJSON),
		SecretRef:    secretRef,
		CreatedAt:    now,
	}
	if commitErr := s.Repository.CommitACMEAccount(ctx, account); commitErr != nil {
		if errors.Is(commitErr, store.ErrACMEAccountConflict) {
			cleanupErr := cleanupACMEAccountCommitIntent(context.WithoutCancel(ctx), s.Repository, s.Secrets, intent)
			return domain.ACMEAccount{}, errors.Join(commitErr, cleanupErr)
		}
		pending, inspectErr := ACMEAccountCommitIntentPending(context.WithoutCancel(ctx), s.Repository, account.ID)
		if inspectErr != nil {
			return domain.ACMEAccount{}, errors.Join(
				fmt.Errorf("ACME account commit outcome is unknown; key was preserved: %w", commitErr),
				fmt.Errorf("inspect ACME account commit journal: %w", inspectErr),
			)
		}
		if !pending {
			return account, nil
		}
		cleanupErr := cleanupACMEAccountCommitIntent(context.WithoutCancel(ctx), s.Repository, s.Secrets, intent)
		return domain.ACMEAccount{}, errors.Join(fmt.Errorf("save ACME account: %w", commitErr), cleanupErr)
	}
	return account, nil
}

func compensateSecretDelete(ctx context.Context, secrets SecretStore, reference string) error {
	firstErr := secrets.Delete(ctx, reference)
	if firstErr == nil {
		return nil
	}
	if retryErr := secrets.Delete(ctx, reference); retryErr != nil {
		return errors.Join(firstErr, fmt.Errorf("retry secret deletion: %w", retryErr))
	}
	return nil
}

func ACMEAccountCommitIntentPending(ctx context.Context, repository AccountRepository, accountID string) (bool, error) {
	intents, err := repository.ListACMEAccountCommitIntents(ctx)
	if err != nil {
		return false, err
	}
	for _, intent := range intents {
		if intent.AccountID == accountID {
			return true, nil
		}
	}
	return false, nil
}

func cleanupACMEAccountCommitIntent(ctx context.Context, repository AccountRepository, secrets SecretStore, intent domain.ACMEAccountCommitIntent) error {
	if err := validateACMEAccountCommitIntent(intent); err != nil {
		return err
	}
	if err := compensateSecretDelete(ctx, secrets, intent.SecretRef); err != nil {
		return fmt.Errorf("delete orphaned ACME account key: %w", err)
	}
	if err := repository.DeleteACMEAccountCommitIntent(ctx, intent.AccountID); err != nil {
		return fmt.Errorf("close ACME account commit intent: %w", err)
	}
	return nil
}

func validateACMEAccountCommitIntent(intent domain.ACMEAccountCommitIntent) error {
	if intent.AccountID == "" || intent.SecretRef == "" {
		return errors.New("ACME account commit intent is incomplete")
	}
	if err := safePathComponent(intent.AccountID); err != nil {
		return fmt.Errorf("ACME account commit intent account ID: %w", err)
	}
	if len(intent.AccountID) > 128 {
		return errors.New("ACME account commit intent account ID is too long")
	}
	for _, character := range intent.AccountID {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return errors.New("ACME account commit intent account ID contains an unsafe character")
		}
	}
	expected := "acme-account/" + intent.AccountID
	if intent.SecretRef != expected {
		return fmt.Errorf("ACME account commit intent secret reference must equal %q", expected)
	}
	return nil
}

func RecoverACMEAccountCommitIntents(ctx context.Context, repository AccountRepository, secrets SecretStore) error {
	if repository == nil || secrets == nil {
		return errors.New("ACME account commit recovery is not fully configured")
	}
	intents, err := repository.ListACMEAccountCommitIntents(ctx)
	if err != nil {
		return fmt.Errorf("list ACME account commit intents: %w", err)
	}
	var recoveryErrors []error
	for _, intent := range intents {
		if err := cleanupACMEAccountCommitIntent(ctx, repository, secrets, intent); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("recover ACME account %s: %w", intent.AccountID, err))
		}
	}
	return errors.Join(recoveryErrors...)
}

func (s *AccountService) Load(ctx context.Context, environment string) (AccountMaterial, error) {
	if s == nil || s.Repository == nil || s.Secrets == nil {
		return AccountMaterial{}, errors.New("ACME account service is not fully configured")
	}
	account, err := s.Repository.GetACMEAccountByEnvironment(ctx, environment)
	if err != nil {
		return AccountMaterial{}, fmt.Errorf("load %s ACME account: %w", environment, err)
	}
	keyPEM, err := s.Secrets.Get(ctx, account.SecretRef)
	if err != nil {
		return AccountMaterial{}, fmt.Errorf("load ACME account key: %w", err)
	}
	privateKey, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return AccountMaterial{}, fmt.Errorf("parse ACME account key: %w", err)
	}
	var registrationResource acme.ExtendedAccount
	if err := json.Unmarshal([]byte(account.Registration), &registrationResource); err != nil {
		return AccountMaterial{}, fmt.Errorf("parse ACME account registration: %w", err)
	}
	if registrationResource.Location == "" {
		return AccountMaterial{}, errors.New("ACME registration has no account location")
	}
	return AccountMaterial{
		Account:      account,
		PrivateKey:   privateKey,
		Registration: &registrationResource,
	}, nil
}

type legoUser struct {
	email        string
	privateKey   crypto.Signer
	registration *acme.ExtendedAccount
}

func (u *legoUser) GetEmail() string                       { return u.email }
func (u *legoUser) GetRegistration() *acme.ExtendedAccount { return u.registration }
func (u *legoUser) GetPrivateKey() crypto.Signer           { return u.privateKey }
