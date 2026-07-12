package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/app"
	"github.com/MeghdadFadaee/domainops/internal/bootstrap"
	"github.com/MeghdadFadaee/domainops/internal/certificates"
	"github.com/MeghdadFadaee/domainops/internal/domain"
)

func TestVersionJSONEnvelope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Execute(context.Background(), &stdout, &stderr, []string{"--json", "version"}); err != nil {
		t.Fatal(err)
	}
	var envelope Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("decode output %q: %v", stdout.String(), err)
	}
	if !envelope.OK || envelope.SchemaVersion != 1 || envelope.Command != "domainops version" {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestRootJSONRequiresSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Execute(context.Background(), &stdout, &stderr, []string{"--json"})
	if err == nil || !IsReportedError(err) {
		t.Fatalf("root JSON error = %v", err)
	}
	var envelope Envelope
	if decodeErr := json.Unmarshal(stdout.Bytes(), &envelope); decodeErr != nil {
		t.Fatalf("decode output %q: %v", stdout.String(), decodeErr)
	}
	if envelope.OK || envelope.Command != "domainops" || len(envelope.Errors) != 1 || !strings.Contains(envelope.Errors[0], "subcommand") {
		t.Fatalf("root JSON envelope = %#v", envelope)
	}
}

func TestLeafCommandsRejectStrayArgumentsAndConflictingBulkFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--json", "status", "stray"},
		{"--json", "cert", "issue", "--all", "--zone", "example.com"},
	} {
		var stdout, stderr bytes.Buffer
		if err := Execute(context.Background(), &stdout, &stderr, args); err == nil {
			t.Fatalf("unsafe arguments were accepted: %#v", args)
		}
		envelope := decodeSingleEnvelope(t, stdout.Bytes())
		if envelope.OK || len(envelope.Errors) == 0 {
			t.Fatalf("argument error envelope for %#v = %#v", args, envelope)
		}
	}
}

func TestResolveZonesRejectsDuplicateNamesAcrossAccounts(t *testing.T) {
	ctx := context.Background()
	runtime, err := bootstrap.Open(ctx, bootstrap.Options{DataDir: filepath.Join(t.TempDir(), "state"), NoKeyring: true})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	now := time.Now().UTC()
	accounts := []domain.RemoteAccount{
		{ID: "account-a", Provider: domain.ProviderCloudflare, ProviderID: "a", Name: "A", CreatedAt: now},
		{ID: "account-b", Provider: domain.ProviderCloudflare, ProviderID: "b", Name: "B", CreatedAt: now},
	}
	if err := runtime.Repository.SaveAccounts(ctx, accounts, nil); err != nil {
		t.Fatal(err)
	}
	zones := []domain.Zone{
		{ID: "zone-a", Provider: domain.ProviderCloudflare, ProviderID: "a", AccountID: accounts[0].ID, Name: "example.com", Status: domain.ZoneActive},
		{ID: "zone-b", Provider: domain.ProviderCloudflare, ProviderID: "b", AccountID: accounts[1].ID, Name: "example.com", Status: domain.ZoneActive},
	}
	if err := runtime.Repository.SaveZones(ctx, zones); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveZones(ctx, runtime, []string{"example.com"}, false); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate zone name resolution = %v", err)
	}
	ids, err := resolveZones(ctx, runtime, []string{"zone-b"}, false)
	if err != nil || len(ids) != 1 || ids[0] != "zone-b" {
		t.Fatalf("explicit zone ID resolution = %#v, %v", ids, err)
	}
}

func TestZonePreferHelpUsesCredentialIDMetavariable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Execute(context.Background(), &stdout, &stderr, []string{"zone", "prefer", "--help"}); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	help := stdout.String()
	if !strings.Contains(help, "--credential CREDENTIAL_ID") {
		t.Fatalf("credential flag help has the wrong metavariable: %q", help)
	}
	if strings.Contains(help, "--credential domainops account list") {
		t.Fatalf("credential flag help contains a multi-word metavariable: %q", help)
	}
}

func TestStatusInitializesLocalMetadataWithoutVaultUnlock(t *testing.T) {
	var stdout, stderr bytes.Buffer
	dataDir := filepath.Join(t.TempDir(), "state")
	if err := Execute(context.Background(), &stdout, &stderr, []string{"--data-dir", dataDir, "--json", "status"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"zones":0`) || !strings.Contains(stdout.String(), `"schema_version":1`) {
		t.Fatalf("status output = %s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "domainops.db")); err != nil {
		t.Fatal(err)
	}
}

func TestReadSecretRequiresPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecret("test", path, false, &bytes.Buffer{}); err == nil {
		t.Fatal("world-readable secret file unexpectedly accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := readSecret("test", path, false, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "secret" {
		t.Fatalf("value = %q", value)
	}
}

func TestReadDNSBatchFileSupportsVersionedDocumentAndArray(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"document": `{"schema_version":1,"mutations":[{"kind":"create","after":{"type":"A","name":"www","content":"192.0.2.1","ttl":300}}]}`,
		"array":    `[{"kind":"delete","record_id":"cfrecord_1"}]`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "batch.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			mutations, err := readDNSBatchFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(mutations) != 1 || mutations[0].Kind == "" {
				t.Fatalf("mutations = %#v", mutations)
			}
		})
	}
}

func TestReadDNSBatchFileRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "batch.json")
	if err := os.WriteFile(path, []byte(`[{"kind":"create","after":{"type":"A","name":"www","contnet":"192.0.2.1","ttl":300}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDNSBatchFile(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown DNS field error = %v", err)
	}
}

func TestRenewDueFlagIsRequiredAndJSONErrorIsReportedOnce(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Execute(context.Background(), &stdout, &stderr, []string{"--json", "cert", "renew"})
	if err == nil {
		t.Fatal("renew without --due unexpectedly succeeded")
	}
	if !IsReportedError(err) {
		t.Fatalf("error was not marked as JSON-reported: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	envelope := decodeSingleEnvelope(t, stdout.Bytes())
	if envelope.OK || envelope.Command != "domainops cert renew" || len(envelope.Errors) != 1 || !strings.Contains(envelope.Errors[0], "due") {
		t.Fatalf("envelope = %#v", envelope)
	}

	command, _, findErr := NewRoot(io.Discard, io.Discard).Find([]string{"cert", "renew"})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if command.Flags().Lookup("due") == nil {
		t.Fatal("renew command does not register --due")
	}
}

func TestOperationErrorsUseSingleFailedJSONEnvelopeAndAccurateExitCode(t *testing.T) {
	t.Run("sync", func(t *testing.T) {
		dataDir, passwordFile := seedUnlockedRuntime(t, func(runtime *bootstrap.Runtime) {
			now := time.Now().UTC()
			err := runtime.Repository.SaveCredential(context.Background(), domain.Credential{
				ID: "cred_missing_secret", Provider: domain.ProviderCloudflare, Label: "Broken token",
				Kind: domain.CredentialUserToken, SecretRef: "secret-does-not-exist",
				Status: domain.CredentialUnknown, CreatedAt: now,
			})
			if err != nil {
				t.Fatal(err)
			}
		})
		assertPartialJSONExit3(t, []string{
			"--data-dir", dataDir, "--no-keyring", "--vault-password-file", passwordFile,
			"--json", "sync", "--skip-health",
		}, "domainops sync")
	})

	t.Run("issue", func(t *testing.T) {
		dataDir, passwordFile := seedUnlockedRuntime(t, func(runtime *bootstrap.Runtime) {
			now := time.Now().UTC()
			account := domain.RemoteAccount{ID: "cfacct_test", Provider: domain.ProviderCloudflare, ProviderID: "test", Name: "Test", CreatedAt: now}
			if err := runtime.Repository.SaveAccounts(context.Background(), []domain.RemoteAccount{account}, nil); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Repository.SaveZones(context.Background(), []domain.Zone{{
				ID: "cfzone_test", Provider: domain.ProviderCloudflare, ProviderID: "test", AccountID: account.ID,
				PreferredCredentialID: "cred_test", Name: "example.com", Status: domain.ZoneActive,
			}}); err != nil {
				t.Fatal(err)
			}
		})
		assertJSONExitCode(t, []string{
			"--data-dir", dataDir, "--no-keyring", "--vault-password-file", passwordFile,
			"--json", "cert", "issue", "--zone", "example.com",
		}, "domainops cert issue", 1)
	})

	t.Run("renew", func(t *testing.T) {
		dataDir, passwordFile := seedUnlockedRuntime(t, nil)
		assertJSONExitCode(t, []string{
			"--data-dir", dataDir, "--no-keyring", "--vault-password-file", passwordFile,
			"--json", "cert", "renew", "--due", "--confirm-production",
		}, "domainops cert renew", 1)
	})
}

func TestCertificateOperationExitCodeDistinguishesGlobalAndPerItemFailure(t *testing.T) {
	if code := certificateOperationExitCode(app.IssueZonesResult{}); code != 1 {
		t.Fatalf("global certificate failure exit code = %d", code)
	}
	if code := certificateOperationExitCode(app.IssueZonesResult{Failed: []app.IssueFailure{{ZoneID: "zone", Error: "failed"}}}); code != 3 {
		t.Fatalf("per-item certificate failure exit code = %d", code)
	}
}

func TestCertificateActivationWarningsAreTopLevelPartialJSON(t *testing.T) {
	result := app.IssueZonesResult{Completed: []certificates.CommitResult{{
		Lineage:  domain.CertificateLineage{ID: "lineage", Name: "example.com"},
		Warnings: []string{"current symlink activation failed"},
	}}}
	warnings := certificateResultWarnings(result)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "example.com") {
		t.Fatalf("certificate warnings = %#v", warnings)
	}
	var stdout bytes.Buffer
	opts := &options{json: true, stdout: &stdout, stderr: io.Discard}
	if err := writeOperationOutput(opts, "domainops cert issue", result, "partial", nil, warnings...); err != nil {
		t.Fatal(err)
	}
	envelope := decodeSingleEnvelope(t, stdout.Bytes())
	if envelope.OK || len(envelope.Warnings) != 1 || len(envelope.Errors) != 0 || !opts.jsonReported {
		t.Fatalf("activation warning envelope = %#v reported=%v", envelope, opts.jsonReported)
	}
}

func TestPlainCertificateListIncludesLineageID(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	runtime, err := bootstrap.Open(context.Background(), bootstrap.Options{DataDir: dataDir, NoKeyring: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lineage := domain.CertificateLineage{
		ID: "lineage_example", Name: "example.com", Source: domain.CertificateImported,
		Identifiers: []string{"example.com", "*.example.com"}, KeyAlgorithm: domain.KeyECDSAP256,
		Profile: "classic", CreatedAt: now, UpdatedAt: now,
	}
	if err := runtime.Repository.SaveCertificateLineage(context.Background(), lineage); err != nil {
		_ = runtime.Close()
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := Execute(context.Background(), &stdout, &stderr, []string{"--data-dir", dataDir, "--no-keyring", "cert", "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), lineage.ID) {
		t.Fatalf("certificate list omitted lineage ID: %q", stdout.String())
	}
}

func seedUnlockedRuntime(t *testing.T, seed func(*bootstrap.Runtime)) (string, string) {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "state")
	runtime, err := bootstrap.Open(context.Background(), bootstrap.Options{DataDir: dataDir, NoKeyring: true})
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("correct horse battery staple")
	if err := runtime.Application.UnlockVault(context.Background(), password); err != nil {
		_ = runtime.Close()
		t.Fatal(err)
	}
	if seed != nil {
		seed(runtime)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(root, "vault-password")
	if err := os.WriteFile(passwordFile, password, 0o600); err != nil {
		t.Fatal(err)
	}
	return dataDir, passwordFile
}

func assertPartialJSONExit3(t *testing.T, args []string, command string) {
	assertJSONExitCode(t, args, command, 3)
}

func assertJSONExitCode(t *testing.T, args []string, command string, code int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := Execute(context.Background(), &stdout, &stderr, args)
	if err == nil {
		t.Fatal("partial operation unexpectedly succeeded")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != code {
		t.Fatalf("error = %v, want exit code %d", err, code)
	}
	if !IsReportedError(err) {
		t.Fatalf("error was not marked as JSON-reported: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	envelope := decodeSingleEnvelope(t, stdout.Bytes())
	if envelope.OK || envelope.Command != command || envelope.Data == nil || len(envelope.Errors) == 0 {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func decodeSingleEnvelope(t *testing.T, data []byte) Envelope {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("decode output %q: %v", data, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("output contained more than one JSON value: %q (next decode: %v)", data, err)
	}
	return envelope
}
