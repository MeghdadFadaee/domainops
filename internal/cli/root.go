package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/MeghdadFadaee/domainops/internal/app"
	"github.com/MeghdadFadaee/domainops/internal/bootstrap"
	"github.com/MeghdadFadaee/domainops/internal/buildinfo"
	"github.com/MeghdadFadaee/domainops/internal/certificates"
	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/tui"
)

type options struct {
	dataDir           string
	json              bool
	noKeyring         bool
	vaultPasswordFile string
	stdout            io.Writer
	stderr            io.Writer
	jsonReported      bool
}

type Envelope struct {
	SchemaVersion int         `json:"schema_version"`
	OK            bool        `json:"ok"`
	Command       string      `json:"command"`
	GeneratedAt   time.Time   `json:"generated_at"`
	Data          interface{} `json:"data,omitempty"`
	Warnings      []string    `json:"warnings,omitempty"`
	Errors        []string    `json:"errors,omitempty"`
}

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

type reportedError struct{ err error }

func (e *reportedError) Error() string { return e.err.Error() }
func (e *reportedError) Unwrap() error { return e.err }

// IsReportedError reports whether Execute already emitted the error as a JSON
// envelope. Callers should still inspect wrapped ExitError values for the exit
// status, but must not print the error a second time.
func IsReportedError(err error) bool {
	var reported *reportedError
	return errors.As(err, &reported)
}

func NewRoot(stdout, stderr io.Writer) *cobra.Command {
	root, _ := newRoot(stdout, stderr)
	return root
}

func newRoot(stdout, stderr io.Writer) (*cobra.Command, *options) {
	opts := &options{stdout: stdout, stderr: stderr}
	root := &cobra.Command{
		Use:           "domainops",
		Short:         "Professional domain and certificate operations console",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.json {
				return errors.New("a subcommand is required with --json")
			}
			return runTUI(cmd.Context(), opts)
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().StringVar(&opts.dataDir, "data-dir", "", "override the DomainOps data directory")
	root.PersistentFlags().BoolVar(&opts.json, "json", false, "emit versioned machine-readable JSON")
	root.PersistentFlags().BoolVar(&opts.noKeyring, "no-keyring", false, "disable optional OS keyring auto-unlock")
	root.PersistentFlags().StringVar(&opts.vaultPasswordFile, "vault-password-file", "", "read the vault password from a private file")

	root.AddCommand(newStatusCommand(opts))
	root.AddCommand(newSyncCommand(opts))
	root.AddCommand(newAccountCommand(opts))
	root.AddCommand(newZoneCommand(opts))
	root.AddCommand(newDNSCommand(opts))
	root.AddCommand(newCertificateCommand(opts))
	root.AddCommand(newHealthCommand(opts))
	root.AddCommand(&cobra.Command{
		Use: "version", Short: "Print build information",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			data := map[string]string{"version": buildinfo.Version, "commit": buildinfo.Commit, "date": buildinfo.Date}
			return writeOutput(opts, cmd.CommandPath(), data, fmt.Sprintf("DomainOps %s (%s, %s)", buildinfo.Version, buildinfo.Commit, buildinfo.Date))
		},
	})
	return root, opts
}

func Execute(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	command, opts := newRoot(stdout, stderr)
	command.SetArgs(args)
	executed, err := command.ExecuteContextC(ctx)
	if err == nil {
		return nil
	}
	if !opts.json && !jsonRequested(args) {
		return err
	}
	if opts.jsonReported {
		return &reportedError{err: err}
	}
	commandName := command.CommandPath()
	if executed != nil {
		commandName = executed.CommandPath()
	}
	if reportErr := writeJSONEnvelope(opts, Envelope{
		SchemaVersion: 1,
		OK:            false,
		Command:       commandName,
		GeneratedAt:   time.Now().UTC(),
		Errors:        []string{err.Error()},
	}); reportErr != nil {
		return errors.Join(err, fmt.Errorf("write JSON error envelope: %w", reportErr))
	}
	return &reportedError{err: err}
}

func jsonRequested(args []string) bool {
	enabled := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		switch {
		case arg == "--json":
			enabled = true
		case strings.HasPrefix(arg, "--json="):
			value, err := strconv.ParseBool(strings.TrimPrefix(arg, "--json="))
			if err != nil {
				// The flag parser will report the invalid value; honoring the
				// requested output mode keeps that error machine-readable.
				enabled = true
			} else {
				enabled = value
			}
		}
	}
	return enabled
}

func runTUI(ctx context.Context, opts *options) error {
	runtime, err := bootstrap.Open(ctx, bootstrap.Options{DataDir: opts.dataDir, NoKeyring: opts.noKeyring})
	if err != nil {
		return err
	}
	defer runtime.Close()
	_, statErr := os.Stat(runtime.Paths.Vault)
	passwordFile := opts.vaultPasswordFile
	if passwordFile == "" {
		passwordFile = os.Getenv("DOMAINOPS_VAULT_PASSWORD_FILE")
	}
	if passwordFile != "" {
		if err := unlockRuntime(ctx, runtime, opts); err != nil && !app.IsRecoveryWarning(err) {
			return err
		}
	}
	model := tui.New(runtime.Application, tui.Options{FirstRun: errors.Is(statErr, os.ErrNotExist), Version: buildinfo.Version})
	program := tea.NewProgram(model)
	_, err = program.Run()
	return err
}

func newStatusCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: "Show the cached operational dashboard",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			snapshot, err := runtime.Application.Dashboard(cmd.Context())
			if err != nil {
				return err
			}
			plain := fmt.Sprintf("Accounts: %d  Zones: %d  DNS: %d  Certificates: %d  Due: %d  Expired: %d  Issues: %d",
				snapshot.Accounts, snapshot.Zones, snapshot.DNSRecords, snapshot.Certificates,
				snapshot.CertificatesDue, snapshot.CertificatesExpired, len(snapshot.Issues))
			return writeOutput(opts, cmd.CommandPath(), snapshot, plain)
		},
	}
}

func newSyncCommand(opts *options) *cobra.Command {
	var skipHealth bool
	command := &cobra.Command{
		Use: "sync", Short: "Synchronize all Cloudflare accounts and public health observations",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			if skipHealth {
				runtime.Application.SetHealthCheck(nil)
			}
			jobs, syncErr := runtime.Application.SyncAll(cmd.Context())
			snapshot, dashboardErr := runtime.Application.Dashboard(cmd.Context())
			if dashboardErr != nil {
				return errors.Join(syncErr, dashboardErr)
			}
			data := struct {
				Jobs      []domain.Job             `json:"jobs"`
				Dashboard domain.DashboardSnapshot `json:"dashboard"`
			}{jobs, snapshot}
			if outErr := writeOperationOutput(opts, cmd.CommandPath(), data, fmt.Sprintf("Synchronized %d connection(s); %d zones cached", len(jobs), snapshot.Zones), syncErr); outErr != nil {
				return outErr
			}
			if syncErr != nil {
				return &ExitError{Code: 3, Err: syncErr}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&skipHealth, "skip-health", false, "skip DNS and public TLS endpoint checks")
	return command
}

func newAccountCommand(opts *options) *cobra.Command {
	account := &cobra.Command{Use: "account", Short: "Manage provider connections"}
	var label, accountID, tokenFile string
	add := &cobra.Command{
		Use: "add", Short: "Add and verify a scoped Cloudflare API token",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			token, err := readSecret("Cloudflare API token", tokenFile, false, opts.stderr)
			if err != nil {
				return err
			}
			defer wipe(token)
			kind := domain.CredentialUserToken
			if strings.TrimSpace(accountID) != "" {
				kind = domain.CredentialAccountToken
			}
			credential, err := runtime.Application.AddCloudflareCredential(cmd.Context(), app.AddCredentialInput{
				Label: label, Token: string(token), Kind: kind, AccountID: accountID,
			})
			if err != nil {
				return err
			}
			return writeOutput(opts, cmd.CommandPath(), credential, "Cloudflare connection added: "+credential.Label)
		},
	}
	add.Flags().StringVar(&label, "label", "Cloudflare", "connection label")
	add.Flags().StringVar(&accountID, "account-id", "", "required only for account-owned tokens")
	add.Flags().StringVar(&tokenFile, "token-file", "", "read the API token from a private file")
	account.AddCommand(add)
	account.AddCommand(&cobra.Command{
		Use: "list", Short: "List configured connections",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			values, err := runtime.Application.Credentials(cmd.Context())
			if err != nil {
				return err
			}
			var lines []string
			for _, value := range values {
				lines = append(lines, fmt.Sprintf("%-28s %-24s %-16s %s", value.ID, value.Label, value.Kind, value.Status))
			}
			if len(lines) == 0 {
				lines = []string{"No provider connections configured."}
			}
			return writeOutput(opts, cmd.CommandPath(), values, strings.Join(lines, "\n"))
		},
	})
	var removeConfirmation string
	remove := &cobra.Command{
		Use: "remove CREDENTIAL_ID", Short: "Remove a Cloudflare connection and its encrypted token",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			credential, err := runtime.Repository.GetCredential(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if removeConfirmation != credential.Label {
				return fmt.Errorf("removal confirmation must exactly match %q", credential.Label)
			}
			if err := runtime.Application.DeleteCredential(cmd.Context(), credential.ID); err != nil {
				return err
			}
			return writeOutput(opts, cmd.CommandPath(), map[string]string{"credential_id": credential.ID, "status": "removed"}, "Removed Cloudflare connection "+credential.Label)
		},
	}
	remove.Flags().StringVar(&removeConfirmation, "confirm", "", "type the exact connection label")
	_ = remove.MarkFlagRequired("confirm")
	account.AddCommand(remove)
	return account
}

func newDNSCommand(opts *options) *cobra.Command {
	dns := &cobra.Command{Use: "dns", Short: "Inspect and safely batch Cloudflare DNS records"}
	var listZone string
	list := &cobra.Command{
		Use: "list", Short: "List cached DNS records for one zone",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			zoneIDs, err := resolveZones(cmd.Context(), runtime, []string{listZone}, false)
			if err != nil {
				return err
			}
			records, err := runtime.Application.DNSRecords(cmd.Context(), zoneIDs[0])
			if err != nil {
				return err
			}
			lines := make([]string, 0, len(records))
			for _, record := range records {
				lines = append(lines, fmt.Sprintf("%-28s %-6s %-40s %-8d %s", record.ID, record.Type, record.Name, record.TTL, record.Content))
			}
			if len(lines) == 0 {
				lines = []string{"No cached DNS records for this zone."}
			}
			return writeOutput(opts, cmd.CommandPath(), records, strings.Join(lines, "\n"))
		},
	}
	list.Flags().StringVar(&listZone, "zone", "", "synchronized zone name or local ID")
	_ = list.MarkFlagRequired("zone")

	var batchZone, batchFile string
	var apply bool
	batch := &cobra.Command{
		Use: "batch", Short: "Preview or apply a zone-scoped DNS mutation file",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mutations, err := readDNSBatchFile(batchFile)
			if err != nil {
				return err
			}
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			zoneIDs, err := resolveZones(cmd.Context(), runtime, []string{batchZone}, false)
			if err != nil {
				return err
			}
			if !apply {
				plan, err := runtime.Application.PlanDNSBatch(cmd.Context(), zoneIDs[0], mutations)
				if err != nil {
					return err
				}
				return writeOutput(opts, cmd.CommandPath(), plan, fmt.Sprintf("Previewed %d DNS mutation(s) for %s; rerun with --apply to submit", len(plan.Mutations), plan.ZoneName))
			}
			result, applyErr := runtime.Application.ApplyDNSBatch(cmd.Context(), zoneIDs[0], mutations)
			plain := fmt.Sprintf("Applied %d DNS mutation(s) to %s; %d records reconciled", len(result.Plan.Mutations), result.Plan.ZoneName, len(result.Records))
			if result.OutcomeUnknown {
				plain = fmt.Sprintf("Cloudflare outcome is unknown for %d DNS mutation(s) on %s; %d records were refreshed for review", len(result.Plan.Mutations), result.Plan.ZoneName, len(result.Records))
			} else if applyErr != nil && !result.Applied {
				plain = fmt.Sprintf("Cloudflare rejected %d DNS mutation(s) for %s; no applied result was reported", len(result.Plan.Mutations), result.Plan.ZoneName)
			}
			if outErr := writeOperationOutput(opts, cmd.CommandPath(), result, plain, applyErr); outErr != nil {
				return outErr
			}
			if applyErr != nil {
				code := 1
				if result.Applied || result.OutcomeUnknown {
					code = 3
				}
				return &ExitError{Code: code, Err: applyErr}
			}
			return nil
		},
	}
	batch.Flags().StringVar(&batchZone, "zone", "", "synchronized zone name or local ID")
	batch.Flags().StringVar(&batchFile, "file", "", "JSON mutation file (schema version 1 or a mutation array)")
	batch.Flags().BoolVar(&apply, "apply", false, "submit the validated batch; otherwise preview only")
	_ = batch.MarkFlagRequired("zone")
	_ = batch.MarkFlagRequired("file")

	dns.AddCommand(list, batch)
	return dns
}

func newZoneCommand(opts *options) *cobra.Command {
	zoneCommand := &cobra.Command{Use: "zone", Short: "Inspect zones and control explicit credential routing"}
	zoneCommand.AddCommand(&cobra.Command{
		Use: "list", Short: "List cached zones and their preferred connections",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			zones, err := runtime.Application.Zones(cmd.Context())
			if err != nil {
				return err
			}
			lines := make([]string, 0, len(zones))
			for _, zone := range zones {
				lines = append(lines, fmt.Sprintf("%-28s %-36s %-14s %s", zone.ID, zone.Name, zone.Status, zone.PreferredCredentialID))
			}
			if len(lines) == 0 {
				lines = []string{"No synchronized zones."}
			}
			return writeOutput(opts, cmd.CommandPath(), zones, strings.Join(lines, "\n"))
		},
	})
	var credentialID, confirmation string
	prefer := &cobra.Command{
		Use: "prefer ZONE", Short: "Assign and live-verify a zone's preferred credential",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			zoneIDs, err := resolveZones(cmd.Context(), runtime, []string{args[0]}, false)
			if err != nil {
				return err
			}
			zone, err := runtime.Repository.GetZone(cmd.Context(), zoneIDs[0])
			if err != nil {
				return err
			}
			if confirmation != zone.Name {
				return fmt.Errorf("preference confirmation must exactly match %q", zone.Name)
			}
			updated, err := runtime.Application.SetZonePreferredCredential(cmd.Context(), zone.ID, credentialID)
			if err != nil {
				return err
			}
			return writeOutput(opts, cmd.CommandPath(), updated, "Preferred credential updated for "+updated.Name)
		},
	}
	prefer.Flags().StringVar(&credentialID, "credential", "", "select the `CREDENTIAL_ID` shown by domainops account list")
	prefer.Flags().StringVar(&confirmation, "confirm", "", "type the exact zone name")
	_ = prefer.MarkFlagRequired("credential")
	_ = prefer.MarkFlagRequired("confirm")
	zoneCommand.AddCommand(prefer)
	return zoneCommand
}

type dnsBatchFile struct {
	SchemaVersion int                  `json:"schema_version"`
	Mutations     []domain.DNSMutation `json:"mutations"`
}

func readDNSBatchFile(path string) ([]domain.DNSMutation, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect DNS batch file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("DNS batch file is not a regular file")
	}
	const maximum = 4 << 20
	if info.Size() > maximum {
		return nil, fmt.Errorf("DNS batch file exceeds %d bytes", maximum)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read DNS batch file: %w", err)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("DNS batch file is empty")
	}
	var mutations []domain.DNSMutation
	if trimmed[0] == '[' {
		err = decodeStrictJSON(body, &mutations)
	} else {
		var document dnsBatchFile
		if err = decodeStrictJSON(body, &document); err == nil {
			if document.SchemaVersion != 0 && document.SchemaVersion != 1 {
				return nil, fmt.Errorf("unsupported DNS batch schema version %d", document.SchemaVersion)
			}
			mutations = document.Mutations
		}
	}
	if err != nil {
		return nil, fmt.Errorf("decode DNS batch file: %w", err)
	}
	if len(mutations) == 0 {
		return nil, errors.New("DNS batch file contains no mutations")
	}
	return mutations, nil
}

func decodeStrictJSON(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func newCertificateCommand(opts *options) *cobra.Command {
	certificate := &cobra.Command{Use: "cert", Short: "Issue, inspect, renew, import, and export certificates"}
	certificate.AddCommand(newACMEAccountCommand(opts))
	certificate.AddCommand(newCertIssueCommand(opts))
	certificate.AddCommand(newCertRenewCommand(opts))
	certificate.AddCommand(newCertImportCommand(opts))
	certificate.AddCommand(newCertExportCommand(opts))
	certificate.AddCommand(newCertRevokeCommand(opts))
	certificate.AddCommand(&cobra.Command{
		Use: "list", Short: "List certificate lineages",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			values, err := runtime.Application.CertificateInventory(cmd.Context())
			if err != nil {
				return err
			}
			var lines []string
			for _, value := range values {
				expires := "—"
				if value.Current != nil {
					expires = value.Current.NotAfter.Local().Format("2006-01-02")
				}
				lines = append(lines, fmt.Sprintf("%-28s %-30s %-10s %-9s %-12s %s", value.Lineage.ID, value.Lineage.Name, value.Environment, value.Status, expires, strings.Join(value.Lineage.Identifiers, ", ")))
			}
			if len(lines) == 0 {
				lines = []string{"No certificates tracked."}
			}
			return writeOutput(opts, cmd.CommandPath(), values, strings.Join(lines, "\n"))
		},
	})
	return certificate
}

func newACMEAccountCommand(opts *options) *cobra.Command {
	var environment, email string
	var acceptTerms bool
	command := &cobra.Command{
		Use: "account-register", Short: "Register a staging or production Let’s Encrypt account",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			account, err := runtime.Certificates.RegisterAccount(cmd.Context(), environment, email, acceptTerms)
			if err != nil {
				return err
			}
			return writeOutput(opts, cmd.CommandPath(), account, "Registered Let’s Encrypt "+environment+" account")
		},
	}
	command.Flags().StringVar(&environment, "environment", certificates.EnvironmentStaging, "staging or production")
	command.Flags().StringVar(&email, "email", "", "ACME contact email")
	command.Flags().BoolVar(&acceptTerms, "accept-tos", false, "explicitly accept the CA terms of service")
	_ = command.MarkFlagRequired("email")
	return command
}

func newCertIssueCommand(opts *options) *cobra.Command {
	var zoneValues, nested []string
	var environment, email, key string
	var all, acceptTerms, confirmProduction bool
	command := &cobra.Command{
		Use: "issue", Short: "Issue independent apex-plus-wildcard certificates",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			zoneIDs, err := resolveZones(cmd.Context(), runtime, zoneValues, all)
			if err != nil {
				return err
			}
			algorithm := domain.KeyAlgorithm(strings.ToUpper(key))
			result, issueErr := runtime.Certificates.IssueZones(cmd.Context(), app.IssueZonesRequest{
				ZoneIDs: zoneIDs, NestedNames: nested, Environment: environment, Email: email,
				AcceptTerms: acceptTerms, ConfirmProduction: confirmProduction, KeyAlgorithm: algorithm,
			})
			plain := fmt.Sprintf("Issued %d certificate(s); %d failed", len(result.Completed), len(result.Failed))
			if warnings := result.WarningCount(); warnings > 0 {
				plain += fmt.Sprintf("; %d activation warning(s)", warnings)
			}
			warnings := certificateResultWarnings(result)
			if outErr := writeOperationOutput(opts, cmd.CommandPath(), result, plain, issueErr, warnings...); outErr != nil {
				return outErr
			}
			if issueErr != nil {
				return &ExitError{Code: certificateOperationExitCode(result), Err: issueErr}
			}
			if len(warnings) > 0 {
				return &ExitError{Code: 3, Err: errors.New("certificate metadata committed with current-link activation warnings")}
			}
			return nil
		},
	}
	command.Flags().StringSliceVar(&zoneValues, "zone", nil, "zone name or local ID; repeat for multiple zones")
	command.Flags().BoolVar(&all, "all", false, "issue for every synchronized zone")
	command.Flags().StringSliceVar(&nested, "nested", nil, "nested hostname/label to include with its wildcard")
	command.Flags().StringVar(&environment, "environment", certificates.EnvironmentStaging, "staging or production")
	command.Flags().StringVar(&email, "email", "", "register this ACME contact email if needed")
	command.Flags().StringVar(&key, "key", string(domain.KeyECDSAP256), "EC256 or RSA2048")
	command.Flags().BoolVar(&acceptTerms, "accept-tos", false, "accept CA terms when registering a missing account")
	command.Flags().BoolVar(&confirmProduction, "confirm-production", false, "confirm production issuance and rate-limit impact")
	command.MarkFlagsMutuallyExclusive("zone", "all")
	return command
}

func newCertRenewCommand(opts *options) *cobra.Command {
	var environment string
	var due, confirmProduction bool
	command := &cobra.Command{
		Use: "renew", Short: "Renew every managed certificate currently due",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !due {
				return errors.New("--due must be explicitly enabled")
			}
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			result, renewErr := runtime.Certificates.RenewDue(cmd.Context(), environment, confirmProduction)
			plain := fmt.Sprintf("Renewed %d certificate(s); %d failed", len(result.Completed), len(result.Failed))
			if warnings := result.WarningCount(); warnings > 0 {
				plain += fmt.Sprintf("; %d activation warning(s)", warnings)
			}
			warnings := certificateResultWarnings(result)
			if outErr := writeOperationOutput(opts, cmd.CommandPath(), result, plain, renewErr, warnings...); outErr != nil {
				return outErr
			}
			if renewErr != nil {
				return &ExitError{Code: certificateOperationExitCode(result), Err: renewErr}
			}
			if len(warnings) > 0 {
				return &ExitError{Code: 3, Err: errors.New("certificate metadata committed with current-link activation warnings")}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&due, "due", false, "renew only certificates currently inside their renewal window")
	command.Flags().StringVar(&environment, "environment", certificates.EnvironmentProduction, "staging or production")
	command.Flags().BoolVar(&confirmProduction, "confirm-production", false, "confirm production renewal")
	_ = command.MarkFlagRequired("due")
	return command
}

func certificateOperationExitCode(result app.IssueZonesResult) int {
	if len(result.Completed) > 0 || len(result.Failed) > 0 {
		return 3
	}
	return 1
}

func certificateResultWarnings(result app.IssueZonesResult) []string {
	var warnings []string
	for _, completed := range result.Completed {
		name := completed.Lineage.Name
		if name == "" {
			name = completed.Lineage.ID
		}
		for _, warning := range completed.Warnings {
			warnings = append(warnings, name+": "+warning)
		}
	}
	return warnings
}

func newCertImportCommand(opts *options) *cobra.Command {
	var path, name, zone string
	command := &cobra.Command{
		Use: "import", Short: "Import public PEM metadata without a private key",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			zoneID := ""
			if zone != "" {
				ids, resolveErr := resolveZones(cmd.Context(), runtime, []string{zone}, false)
				if resolveErr != nil {
					return resolveErr
				}
				zoneID = ids[0]
			}
			lineage, version, err := runtime.Certificates.ImportMetadata(cmd.Context(), path, name, zoneID)
			if err != nil {
				return err
			}
			return writeOutput(opts, cmd.CommandPath(), map[string]any{"lineage": lineage, "version": version}, "Imported certificate metadata for "+lineage.Name)
		},
	}
	command.Flags().StringVar(&path, "file", "", "certificate or full-chain PEM file")
	command.Flags().StringVar(&name, "name", "", "optional lineage display name")
	command.Flags().StringVar(&zone, "zone", "", "optional synchronized zone name or ID")
	_ = command.MarkFlagRequired("file")
	return command
}

func newCertExportCommand(opts *options) *cobra.Command {
	var destination string
	command := &cobra.Command{
		Use: "export LINEAGE_ID", Short: "Export the current managed PEM files",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			result, exportErr := runtime.Certificates.Export(cmd.Context(), args[0], destination)
			if exportErr != nil && result.VersionDirectory == "" {
				return exportErr
			}
			plain := "Exported certificate files to " + result.VersionDirectory
			if exportErr != nil {
				plain = "Certificate files were installed, but current-link activation needs reconciliation at " + result.VersionDirectory
			}
			if outErr := writeOperationOutput(opts, cmd.CommandPath(), result, plain, exportErr); outErr != nil {
				return outErr
			}
			if exportErr != nil {
				return &ExitError{Code: 3, Err: exportErr}
			}
			return nil
		},
	}
	command.Flags().StringVar(&destination, "to", "", "destination root directory")
	_ = command.MarkFlagRequired("to")
	return command
}

func newCertRevokeCommand(opts *options) *cobra.Command {
	var environment, confirmation string
	var reason uint
	command := &cobra.Command{
		Use: "revoke LINEAGE_ID", Short: "Irreversibly revoke the current managed certificate",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime, err := openUnlockedRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			var reasonPointer *uint
			if cmd.Flags().Changed("reason") {
				reasonPointer = &reason
			}
			if err := runtime.Certificates.Revoke(cmd.Context(), args[0], environment, confirmation, reasonPointer); err != nil {
				return err
			}
			return writeOutput(opts, cmd.CommandPath(), map[string]string{"lineage_id": args[0], "status": "revoked"}, "Certificate revoked")
		},
	}
	command.Flags().StringVar(&environment, "environment", certificates.EnvironmentProduction, "staging or production ACME account")
	command.Flags().StringVar(&confirmation, "confirm", "", "type the exact lineage name to authorize revocation")
	command.Flags().UintVar(&reason, "reason", 0, "optional RFC 5280 revocation reason code")
	_ = command.MarkFlagRequired("confirm")
	return command
}

func newHealthCommand(opts *options) *cobra.Command {
	health := &cobra.Command{Use: "health", Short: "Check configured public DNS/TLS endpoints"}
	health.AddCommand(&cobra.Command{
		Use: "check", Short: "Run one bounded health-check cycle",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := openRuntime(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer runtime.Close()
			checkErr := runtime.Health.RunOnce(cmd.Context())
			snapshot, err := runtime.Application.Dashboard(cmd.Context())
			if err != nil {
				return errors.Join(checkErr, err)
			}
			if outErr := writeOperationOutput(opts, cmd.CommandPath(), snapshot.Issues, fmt.Sprintf("Health check complete: %d finding(s)", len(snapshot.Issues)), checkErr); outErr != nil {
				return outErr
			}
			if checkErr != nil {
				return &ExitError{Code: 3, Err: checkErr}
			}
			return nil
		},
	})
	return health
}

func openRuntime(ctx context.Context, opts *options) (*bootstrap.Runtime, error) {
	return bootstrap.Open(ctx, bootstrap.Options{DataDir: opts.dataDir, NoKeyring: opts.noKeyring})
}

func openUnlockedRuntime(ctx context.Context, opts *options) (*bootstrap.Runtime, error) {
	runtime, err := openRuntime(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := unlockRuntime(ctx, runtime, opts); err != nil {
		_ = runtime.Close()
		return nil, err
	}
	return runtime, nil
}

func unlockRuntime(ctx context.Context, runtime *bootstrap.Runtime, opts *options) error {
	if !runtime.Vault.Locked() {
		// Keyring auto-unlock happens during bootstrap. Re-enter the application
		// unlock path so crash recovery is retried and any warning is propagated
		// before a headless mutation proceeds.
		return runtime.Application.UnlockVault(ctx, nil)
	}
	passwordFile := opts.vaultPasswordFile
	if passwordFile == "" {
		passwordFile = os.Getenv("DOMAINOPS_VAULT_PASSWORD_FILE")
	}
	firstRun := false
	if _, err := os.Stat(runtime.Paths.Vault); errors.Is(err, os.ErrNotExist) {
		firstRun = true
	}
	password, err := readSecret("Vault password", passwordFile, firstRun, opts.stderr)
	if err != nil {
		return err
	}
	defer wipe(password)
	if firstRun && len(password) < 10 {
		return errors.New("vault password must contain at least 10 characters")
	}
	return runtime.Application.UnlockVault(ctx, password)
}

func readSecret(label, path string, confirm bool, stderr io.Writer) ([]byte, error) {
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("secret file is not a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("secret file %s must not be accessible by group or others", path)
		}
		value, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		// Trim line endings in place so reading a secret file does not create an
		// additional immutable string copy of the token/password. Zero the
		// discarded bytes as well; the caller wipes the returned slice after use.
		end := len(value)
		for end > 0 && (value[end-1] == '\r' || value[end-1] == '\n') {
			end--
		}
		for index := end; index < len(value); index++ {
			value[index] = 0
		}
		return value[:end], nil
	}
	if !term.IsTerminal(os.Stdin.Fd()) {
		return nil, fmt.Errorf("%s is required; use a private file flag", strings.ToLower(label))
	}
	fmt.Fprintf(stderr, "%s: ", label)
	value, err := term.ReadPassword(os.Stdin.Fd())
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprintf(stderr, "Confirm %s: ", strings.ToLower(label))
		again, confirmErr := term.ReadPassword(os.Stdin.Fd())
		fmt.Fprintln(stderr)
		if confirmErr != nil {
			wipe(value)
			return nil, confirmErr
		}
		defer wipe(again)
		if !slices.Equal(value, again) {
			wipe(value)
			return nil, errors.New("passwords do not match")
		}
	}
	return value, nil
}

func resolveZones(ctx context.Context, runtime *bootstrap.Runtime, values []string, all bool) ([]string, error) {
	zones, err := runtime.Application.Zones(ctx)
	if err != nil {
		return nil, err
	}
	if all {
		if len(values) > 0 {
			return nil, errors.New("--all and --zone cannot be used together")
		}
		ids := make([]string, 0, len(zones))
		for _, zone := range zones {
			ids = append(ids, zone.ID)
		}
		if len(ids) == 0 {
			return nil, errors.New("no synchronized zones are available")
		}
		return ids, nil
	}
	if len(values) == 0 {
		return nil, errors.New("provide --zone or --all")
	}
	byID := make(map[string]string, len(zones))
	byName := make(map[string][]string, len(zones))
	for _, zone := range zones {
		byID[zone.ID] = zone.ID
		name := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
		byName[name] = append(byName[name], zone.ID)
	}
	ids := make([]string, 0, len(values))
	for _, value := range values {
		if id, ok := byID[value]; ok {
			ids = append(ids, id)
			continue
		}
		matches := byName[strings.ToLower(strings.TrimSuffix(value, "."))]
		if len(matches) == 0 {
			return nil, fmt.Errorf("zone %q is not synchronized", value)
		}
		if len(matches) > 1 {
			return nil, fmt.Errorf("zone name %q is ambiguous across accounts; use one local zone ID: %s", value, strings.Join(matches, ", "))
		}
		ids = append(ids, matches[0])
	}
	return ids, nil
}

func writeOutput(opts *options, command string, data interface{}, plain string) error {
	return writeOperationOutput(opts, command, data, plain, nil)
}

func writeOperationOutput(opts *options, command string, data interface{}, plain string, operationErr error, warnings ...string) error {
	if opts.json {
		envelope := Envelope{SchemaVersion: 1, OK: operationErr == nil && len(warnings) == 0, Command: command, GeneratedAt: time.Now().UTC(), Data: data, Warnings: warnings}
		if operationErr != nil {
			envelope.Errors = []string{operationErr.Error()}
		}
		return writeJSONEnvelope(opts, envelope)
	}
	_, err := fmt.Fprintln(opts.stdout, plain)
	return err
}

func writeJSONEnvelope(opts *options, envelope Envelope) error {
	if err := json.NewEncoder(opts.stdout).Encode(envelope); err != nil {
		return err
	}
	if !envelope.OK {
		opts.jsonReported = true
	}
	return nil
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func absolute(path string) string {
	value, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return value
}
