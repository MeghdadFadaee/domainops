package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/MeghdadFadaee/domainops/internal/app"
	"github.com/MeghdadFadaee/domainops/internal/domain"
)

type Backend interface {
	VaultLocked() bool
	UnlockVault(context.Context, []byte) error
	Dashboard(context.Context) (domain.DashboardSnapshot, error)
	Credentials(context.Context) ([]domain.Credential, error)
	Accounts(context.Context) ([]domain.RemoteAccount, error)
	Zones(context.Context) ([]domain.Zone, error)
	DNSRecords(context.Context, string) ([]domain.DNSRecord, error)
	Certificates(context.Context) ([]domain.CertificateLineage, error)
	CertificateInventory(context.Context) ([]app.CertificateInventoryItem, error)
	Jobs(context.Context, int) ([]domain.Job, error)
	Audit(context.Context, int) ([]domain.AuditEvent, error)
	AddCloudflareCredential(context.Context, app.AddCredentialInput) (domain.Credential, error)
	SyncAll(context.Context) ([]domain.Job, error)
	CreateDNSRecord(context.Context, string, domain.DNSRecord) (domain.DNSRecord, error)
	PatchDNSRecord(context.Context, string, string, domain.DNSRecord) (domain.DNSRecord, error)
	DeleteDNSRecord(context.Context, string, string) error
	TLSSettings(context.Context, string, bool) (domain.EdgeTLSSettings, error)
	EdgeCertificates(context.Context, string) ([]domain.EdgeCertificate, error)
	UpdateTLSSettings(context.Context, string, domain.EdgeTLSSettings) (domain.EdgeTLSSettings, error)
	IssueCertificates(context.Context, app.IssueZonesRequest) (app.IssueZonesResult, error)
	ImportCertificateMetadata(context.Context, string, string, string) (domain.CertificateLineage, domain.CertificateVersion, error)
	ExportCertificate(context.Context, string, string) (string, error)
	RevokeCertificate(context.Context, string, string, string, *uint) error
	RenewCertificates(context.Context, string, bool) (app.IssueZonesResult, error)
}

type Options struct {
	FirstRun bool
	Version  string
}

type screen int

const (
	screenDashboard screen = iota
	screenAccounts
	screenZones
	screenDNS
	screenCertificates
	screenTLS
	screenActivity
)

var screens = []struct {
	name string
	icon string
}{
	{"Dashboard", "◆"},
	{"Accounts", "◎"},
	{"Zones", "◫"},
	{"DNS Records", "≋"},
	{"Certificates", "◇"},
	{"Cloudflare TLS", "◈"},
	{"Activity", "↻"},
}

type Model struct {
	backend            Backend
	options            Options
	theme              theme
	width              int
	height             int
	screen             screen
	loading            bool
	busy               bool
	busyReleasePending bool
	err                error
	operationErr       error
	toast              string
	toastAt            time.Time

	dashboard        domain.DashboardSnapshot
	recoveryBlocked  bool
	credentials      []domain.Credential
	accounts         []domain.RemoteAccount
	zones            []domain.Zone
	records          []domain.DNSRecord
	lineages         []domain.CertificateLineage
	certificateItems []app.CertificateInventoryItem
	jobs             []domain.Job
	audit            []domain.AuditEvent
	tls              domain.EdgeTLSSettings
	edgeCertificates []domain.EdgeCertificate
	activeDNSZoneID  string
	activeTLSZoneID  string
	tlsSnapshotReady bool
	tlsSnapshotZone  string
	tlsSnapshotAt    time.Time
	loadSequence     uint64
	activeLoad       uint64

	zoneIndex   int
	recordIndex int
	rowOffset   int

	showHelp     bool
	showPalette  bool
	paletteIndex int
	searching    bool
	searchInput  textinput.Model

	unlock       bool
	unlockFirst  bool
	unlockFocus  int
	unlockInputs []textinput.Model

	addCredential    bool
	credentialFocus  int
	credentialInputs []textinput.Model

	editRecord       bool
	recordEditing    bool
	recordFocus      int
	recordInputs     []textinput.Model
	recordProxied    bool
	recordOriginalID string
	confirmRecord    bool
	recordDraft      domain.DNSRecord
	recordDraftEdit  bool
	recordDraftID    string

	confirmDelete    bool
	confirmTLS       bool
	confirmTLSZoneID string
	tlsDraft         domain.EdgeTLSSettings

	certificateAction            string
	certificateFocus             int
	certificateInputs            []textinput.Model
	certificateAcceptTerms       bool
	certificateConfirmProduction bool
	certificateIssueZoneID       string
	certificateIssueZoneValue    string
	certificateLineageID         string
	certificateExpectedName      string
}

type loadMsg struct {
	dashboard        domain.DashboardSnapshot
	credentials      []domain.Credential
	accounts         []domain.RemoteAccount
	zones            []domain.Zone
	records          []domain.DNSRecord
	lineages         []domain.CertificateLineage
	certificateItems []app.CertificateInventoryItem
	jobs             []domain.Job
	audit            []domain.AuditEvent
	tls              domain.EdgeTLSSettings
	tlsReady         bool
	tlsZoneID        string
	tlsLoadedAt      time.Time
	edgeCertificates []domain.EdgeCertificate
	zoneID           string
	releasesBusy     bool
	requestID        uint64
	err              error
}

type operationMsg struct {
	message string
	err     error
	reload  bool
}

type unlockMsg struct{ err error }

type recoveryRetryMsg struct{ err error }

func New(backend Backend, options Options) *Model {
	m := &Model{backend: backend, options: options, theme: newTheme(), width: 100, height: 30}
	m.searchInput = textinput.New()
	m.searchInput.Placeholder = "Filter this view…"
	m.searchInput.Prompt = "/ "
	m.searchInput.SetWidth(40)
	if backend.VaultLocked() {
		m.unlock = true
		m.unlockFirst = options.FirstRun
		m.unlockInputs = makePasswordInputs(options.FirstRun)
		m.unlockInputs[0].Focus()
	}
	return m
}

func makePasswordInputs(first bool) []textinput.Model {
	makeInput := func(placeholder string) textinput.Model {
		input := textinput.New()
		input.Prompt = ""
		input.Placeholder = placeholder
		input.EchoMode = textinput.EchoPassword
		input.EchoCharacter = '•'
		input.SetWidth(42)
		return input
	}
	result := []textinput.Model{makeInput("Vault password")}
	if first {
		result = append(result, makeInput("Confirm vault password"))
	}
	return result
}

func (m *Model) Init() tea.Cmd {
	if m.unlock {
		return textinput.Blink
	}
	return m.startLoad("", false, false)
}

func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resizeInputs()
		return m, nil
	case loadMsg:
		if msg.requestID != m.activeLoad {
			return m, nil
		}
		m.loading = false
		if msg.releasesBusy {
			m.busy = false
			m.busyReleasePending = false
		}
		m.dashboard = msg.dashboard
		m.recoveryBlocked = m.recoveryBlocked || dashboardRecoveryBlocked(msg.dashboard)
		m.credentials = msg.credentials
		m.accounts = msg.accounts
		m.zones = msg.zones
		m.records = msg.records
		m.certificateItems = msg.certificateItems
		if len(msg.certificateItems) > 0 {
			m.lineages = make([]domain.CertificateLineage, len(msg.certificateItems))
			for index := range msg.certificateItems {
				m.lineages[index] = msg.certificateItems[index].Lineage
			}
		} else {
			m.lineages = msg.lineages
		}
		m.jobs = msg.jobs
		m.audit = msg.audit
		if msg.tlsReady && msg.tlsZoneID != "" && msg.tlsZoneID == msg.tls.ZoneID && !msg.tlsLoadedAt.IsZero() && (m.activeTLSZoneID == "" || m.activeTLSZoneID == msg.tlsZoneID) {
			m.activeTLSZoneID = msg.tlsZoneID
			m.tls = msg.tls
			m.tlsDraft = msg.tls
			m.tlsSnapshotReady = true
			m.tlsSnapshotZone = msg.tlsZoneID
			m.tlsSnapshotAt = msg.tlsLoadedAt
			m.edgeCertificates = msg.edgeCertificates
		}
		if m.activeDNSZoneID == "" {
			m.activeDNSZoneID = msg.zoneID
		}
		m.err = errors.Join(msg.err, m.operationErr)
		m.operationErr = nil
		m.clampSelection()
		return m, nil
	case operationMsg:
		m.err = msg.err
		m.operationErr = msg.err
		if msg.err == nil {
			m.toast, m.toastAt = msg.message, time.Now()
		}
		if msg.reload {
			return m, m.startLoad(m.selectedZoneID(), m.screen == screenTLS, true)
		}
		m.busy = false
		m.busyReleasePending = false
		return m, nil
	case unlockMsg:
		m.busy = false
		var nonFatal interface{ NonFatal() bool }
		if msg.err != nil && (!errors.As(msg.err, &nonFatal) || !nonFatal.NonFatal()) {
			m.err = msg.err
			return m, nil
		}
		for i := range m.unlockInputs {
			m.unlockInputs[i].SetValue("")
		}
		m.unlock = false
		m.err = msg.err
		if msg.err != nil {
			m.recoveryBlocked = true
			m.toast, m.toastAt = "Vault unlocked; recovery requires attention", time.Now()
		}
		return m, m.startLoad("", false, false)
	case recoveryRetryMsg:
		if msg.err != nil {
			m.busy = false
			m.recoveryBlocked = true
			m.err = msg.err
			m.toast, m.toastAt = "Crash recovery still requires attention", time.Now()
			return m, nil
		}
		m.recoveryBlocked = false
		m.err = nil
		m.operationErr = nil
		m.toast, m.toastAt = "Crash recovery completed", time.Now()
		return m, m.startLoad(m.selectedZoneID(), m.screen == screenTLS, true)
	}

	if m.terminalUndersized() {
		if key, ok := message.(tea.KeyPressMsg); ok && (key.String() == "q" || key.String() == "ctrl+c") {
			return m, tea.Quit
		}
		return m, nil
	}
	if key, ok := message.(tea.KeyPressMsg); ok && m.recoveryBlocked && key.String() == "R" {
		if m.busy || m.loading {
			message := "An operation is already running"
			if !m.busy {
				message = "Loading the latest zone state"
			}
			m.toast, m.toastAt = message, time.Now()
			return m, nil
		}
		m.busy = true
		m.err = nil
		return m, retryRecoveryCmd(m.backend)
	}

	if m.unlock {
		return m.updateUnlock(message)
	}
	if m.addCredential {
		return m.updateCredentialForm(message)
	}
	if m.editRecord {
		return m.updateRecordForm(message)
	}
	if m.certificateAction != "" {
		return m.updateCertificateForm(message)
	}
	if m.confirmRecord {
		return m.updateRecordConfirmation(message)
	}
	if m.confirmDelete {
		return m.updateDeleteConfirmation(message)
	}
	if m.confirmTLS {
		return m.updateTLSConfirmation(message)
	}
	if m.searching {
		return m.updateSearch(message)
	}
	if m.showHelp || m.showPalette {
		return m.updateOverlay(message)
	}

	key, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	if m.recoveryBlocked && m.isMutationKey(key.String()) {
		m.toast, m.toastAt = "Crash recovery must succeed before mutations are enabled", time.Now()
		return m, nil
	}
	if m.busy && m.isMutationKey(key.String()) {
		m.toast, m.toastAt = "An operation is already running", time.Now()
		return m, nil
	}
	if m.loading && m.isMutationKey(key.String()) {
		m.toast, m.toastAt = "Loading the latest zone state", time.Now()
		return m, nil
	}
	if m.screen == screenTLS && m.isTLSMutationKey(key.String()) && !m.tlsSnapshotReadyForSelectedZone() {
		m.toast, m.toastAt = "Load this zone’s TLS snapshot before editing", time.Now()
		return m, nil
	}
	switch key.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?":
		m.showHelp = true
	case "ctrl+k":
		m.showPalette = true
		m.paletteIndex = 0
	case "/":
		m.searching = true
		m.searchInput.Focus()
		return m, textinput.Blink
	case "r":
		if !m.busy {
			m.busy = true
			return m, syncCmd(m.backend)
		}
	case "a":
		if m.screen == screenAccounts || m.screen == screenDashboard {
			m.openCredentialForm()
			return m, textinput.Blink
		}
	case "n":
		if m.screen == screenDNS && len(m.zones) > 0 {
			m.openRecordForm(false)
			return m, textinput.Blink
		}
		if m.screen == screenCertificates && len(m.zones) > 0 {
			m.openCertificateForm("issue")
			return m, textinput.Blink
		}
	case "i":
		if m.screen == screenCertificates {
			m.openCertificateForm("import")
			return m, textinput.Blink
		}
	case "u":
		if m.screen == screenCertificates && len(m.filteredLineages()) > 0 {
			m.openCertificateForm("renew")
			return m, textinput.Blink
		}
	case "x":
		if m.screen == screenCertificates && len(m.filteredLineages()) > 0 {
			m.openCertificateForm("export")
			return m, textinput.Blink
		}
	case "e":
		if m.screen == screenDNS && len(m.filteredRecords()) > 0 {
			m.openRecordForm(true)
			return m, textinput.Blink
		}
	case "d":
		if m.screen == screenDNS && len(m.filteredRecords()) > 0 {
			m.confirmDelete = true
		}
		if m.screen == screenCertificates && len(m.filteredLineages()) > 0 {
			m.openCertificateForm("revoke")
			return m, textinput.Blink
		}
	case "s":
		if m.screen == screenTLS && m.tlsSnapshotReadyForSelectedZone() {
			m.confirmTLS = true
			m.confirmTLSZoneID = m.selectedZoneID()
		}
	case "m":
		if m.screen == screenTLS {
			m.tlsDraft.Mode = nextValue(m.tlsDraft.Mode, []string{"off", "flexible", "full", "strict"})
		}
	case "h":
		if m.screen == screenTLS {
			m.tlsDraft.AlwaysUseHTTPS = !m.tlsDraft.AlwaysUseHTTPS
		} else if m.screen > 0 {
			return m, m.navigateToScreen(m.screen - 1)
		}
	case "t":
		if m.screen == screenTLS {
			m.tlsDraft.TLS13 = !m.tlsDraft.TLS13
		}
	case "v":
		if m.screen == screenTLS {
			m.tlsDraft.MinimumTLS = nextValue(m.tlsDraft.MinimumTLS, []string{"1.0", "1.1", "1.2", "1.3"})
		}
	case "l":
		if m.screen < screen(len(screens)-1) {
			return m, m.navigateToScreen(m.screen + 1)
		}
	case "1", "2", "3", "4", "5", "6", "7":
		value, _ := strconv.Atoi(key.String())
		return m, m.navigateToScreen(screen(value - 1))
	case "up", "k":
		before := m.selectedZoneID()
		m.moveSelection(-1)
		if m.screen == screenTLS && before != m.selectedZoneID() {
			return m, m.startLoad(m.selectedZoneID(), true, false)
		}
	case "down", "j":
		before := m.selectedZoneID()
		m.moveSelection(1)
		if m.screen == screenTLS && before != m.selectedZoneID() {
			return m, m.startLoad(m.selectedZoneID(), true, false)
		}
	case "enter":
		if m.screen == screenZones && len(m.filteredZones()) > 0 {
			return m, m.navigateToScreen(screenDNS)
		}
	}
	return m, nil
}

func (m *Model) View() tea.View {
	content := m.render()
	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "DomainOps — Domain & Certificate Console"
	view.BackgroundColor = m.theme.bg
	view.ForegroundColor = m.theme.text
	return view
}

func loadDataCmd(backend Backend, zoneID string, refreshTLS, releasesBusy bool, requestID uint64) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		var result loadMsg
		var errs []error
		var err error
		if result.dashboard, err = backend.Dashboard(ctx); err != nil {
			errs = append(errs, err)
		}
		if result.credentials, err = backend.Credentials(ctx); err != nil {
			errs = append(errs, err)
		}
		if result.accounts, err = backend.Accounts(ctx); err != nil {
			errs = append(errs, err)
		}
		if result.zones, err = backend.Zones(ctx); err != nil {
			errs = append(errs, err)
		}
		if result.certificateItems, err = backend.CertificateInventory(ctx); err != nil {
			errs = append(errs, err)
		}
		if result.jobs, err = backend.Jobs(ctx, 50); err != nil {
			errs = append(errs, err)
		}
		if result.audit, err = backend.Audit(ctx, 50); err != nil {
			errs = append(errs, err)
		}
		if zoneID == "" && len(result.zones) > 0 {
			zoneID = result.zones[0].ID
		}
		result.zoneID = zoneID
		if zoneID != "" {
			if records, err := backend.DNSRecords(ctx, zoneID); err == nil {
				result.records = records
			} else {
				errs = append(errs, err)
			}
			if refreshTLS {
				if settings, err := backend.TLSSettings(ctx, zoneID, true); err == nil {
					if settings.ZoneID != "" && settings.ZoneID != zoneID {
						errs = append(errs, fmt.Errorf("TLS snapshot returned zone %q for requested zone %q", settings.ZoneID, zoneID))
					} else {
						loadedAt := time.Now().UTC()
						settings.ZoneID = zoneID
						result.tls = settings
						result.tlsReady = true
						result.tlsZoneID = zoneID
						result.tlsLoadedAt = loadedAt
					}
				} else {
					errs = append(errs, err)
				}
				if certificates, err := backend.EdgeCertificates(ctx, zoneID); err == nil {
					result.edgeCertificates = certificates
				} else {
					errs = append(errs, err)
				}
			}
		}
		result.releasesBusy = releasesBusy
		result.requestID = requestID
		result.err = errors.Join(errs...)
		return result
	}
}

func (m *Model) startLoad(zoneID string, refreshTLS, releasesBusy bool) tea.Cmd {
	if releasesBusy {
		m.busyReleasePending = true
	}
	m.loadSequence++
	m.activeLoad = m.loadSequence
	m.loading = true
	if refreshTLS {
		m.tlsSnapshotReady = false
		m.confirmTLS = false
		m.confirmTLSZoneID = ""
	}
	return loadDataCmd(m.backend, zoneID, refreshTLS, releasesBusy || m.busyReleasePending, m.activeLoad)
}

func syncCmd(backend Backend) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		_, err := backend.SyncAll(ctx)
		return operationMsg{message: "Cloudflare inventory synchronized", err: err, reload: true}
	}
}

func retryRecoveryCmd(backend Backend) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		return recoveryRetryMsg{err: backend.UnlockVault(ctx, nil)}
	}
}

func (m *Model) maybeLoadScreen() tea.Cmd {
	if m.screen == screenDNS {
		return m.startLoad(m.activeDNSZoneID, false, false)
	}
	if m.screen == screenTLS {
		return m.startLoad(m.activeTLSZoneID, true, false)
	}
	return nil
}

func (m *Model) navigateToScreen(target screen) tea.Cmd {
	zoneID := m.zoneIDForNavigation(target)

	m.screen = target
	m.rowOffset = 0
	switch target {
	case screenDNS:
		m.activeDNSZoneID = zoneID
		m.recordIndex = 0
		return m.startLoad(zoneID, false, false)
	case screenTLS:
		m.activeTLSZoneID = zoneID
		return m.startLoad(zoneID, true, false)
	}
	return nil
}

func (m *Model) zoneIDForNavigation(target screen) string {
	if target != screenDNS && target != screenTLS {
		return ""
	}
	if selected := m.selectedZoneID(); selected != "" {
		return selected
	}
	if target == screenDNS && m.activeDNSZoneID != "" {
		return m.activeDNSZoneID
	}
	if target == screenTLS && m.activeTLSZoneID != "" {
		return m.activeTLSZoneID
	}
	if len(m.zones) == 0 {
		return ""
	}
	return m.zones[min(m.zoneIndex, len(m.zones)-1)].ID
}

func (m *Model) terminalUndersized() bool {
	return m.width < 64 || m.height < 18
}

func (m *Model) tlsSnapshotReadyForSelectedZone() bool {
	zoneID := m.selectedZoneID()
	return m.tlsSnapshotReady && zoneID != "" && m.hasZoneID(zoneID) && m.tlsSnapshotZone == zoneID && m.tls.ZoneID == zoneID && !m.tlsSnapshotAt.IsZero()
}

func (m *Model) isTLSMutationKey(key string) bool {
	switch key {
	case "s", "m", "h", "t", "v":
		return true
	default:
		return false
	}
}

func (m *Model) updateUnlock(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyPressMsg); ok {
		if m.busy && key.String() == "enter" {
			m.toast, m.toastAt = "Vault unlock is already running", time.Now()
			return m, nil
		}
		switch key.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "tab", "down":
			m.focusUnlock(1)
			return m, nil
		case "shift+tab", "up":
			m.focusUnlock(-1)
			return m, nil
		case "enter":
			if m.unlockFocus < len(m.unlockInputs)-1 {
				m.focusUnlock(1)
				return m, nil
			}
			password := m.unlockInputs[0].Value()
			if m.unlockFirst && len(password) < 10 {
				m.err = errors.New("vault password must contain at least 10 characters")
				return m, nil
			}
			if m.unlockFirst && password != m.unlockInputs[1].Value() {
				m.err = errors.New("vault passwords do not match")
				return m, nil
			}
			m.busy = true
			copyPassword := []byte(password)
			return m, func() tea.Msg {
				err := m.backend.UnlockVault(context.Background(), copyPassword)
				for i := range copyPassword {
					copyPassword[i] = 0
				}
				return unlockMsg{err: err}
			}
		}
	}
	var cmd tea.Cmd
	m.unlockInputs[m.unlockFocus], cmd = m.unlockInputs[m.unlockFocus].Update(message)
	return m, cmd
}

func (m *Model) focusUnlock(delta int) {
	m.unlockInputs[m.unlockFocus].Blur()
	m.unlockFocus = (m.unlockFocus + delta + len(m.unlockInputs)) % len(m.unlockInputs)
	m.unlockInputs[m.unlockFocus].Focus()
}

func (m *Model) openCredentialForm() {
	newInput := func(placeholder string, secret bool) textinput.Model {
		input := textinput.New()
		input.Prompt = ""
		input.Placeholder = placeholder
		input.SetWidth(48)
		if secret {
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '•'
		}
		return input
	}
	m.credentialInputs = []textinput.Model{
		newInput("Label, e.g. Production", false),
		newInput("Scoped Cloudflare API token", true),
		newInput("Account ID (only for account-owned tokens)", false),
	}
	m.credentialFocus = 0
	m.credentialInputs[0].Focus()
	m.addCredential = true
	m.err = nil
}

func (m *Model) updateCredentialForm(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "esc":
			m.clearCredentialForm()
			return m, nil
		case "tab", "down":
			m.focusCredential(1)
			return m, nil
		case "shift+tab", "up":
			m.focusCredential(-1)
			return m, nil
		case "enter":
			if m.credentialFocus < len(m.credentialInputs)-1 {
				m.focusCredential(1)
				return m, nil
			}
			label := m.credentialInputs[0].Value()
			token := m.credentialInputs[1].Value()
			accountID := m.credentialInputs[2].Value()
			kind := domain.CredentialUserToken
			if strings.TrimSpace(accountID) != "" {
				kind = domain.CredentialAccountToken
			}
			m.busy = true
			m.clearCredentialForm()
			return m, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				_, err := m.backend.AddCloudflareCredential(ctx, app.AddCredentialInput{Label: label, Token: token, Kind: kind, AccountID: accountID})
				return operationMsg{message: "Cloudflare credential added", err: err, reload: true}
			}
		}
	}
	var cmd tea.Cmd
	m.credentialInputs[m.credentialFocus], cmd = m.credentialInputs[m.credentialFocus].Update(message)
	return m, cmd
}

func (m *Model) focusCredential(delta int) {
	m.credentialInputs[m.credentialFocus].Blur()
	m.credentialFocus = (m.credentialFocus + delta + len(m.credentialInputs)) % len(m.credentialInputs)
	m.credentialInputs[m.credentialFocus].Focus()
}

func (m *Model) clearCredentialForm() {
	for i := range m.credentialInputs {
		m.credentialInputs[i].SetValue("")
	}
	m.addCredential = false
}

func (m *Model) openRecordForm(editing bool) {
	newInput := func(placeholder string) textinput.Model {
		input := textinput.New()
		input.Prompt = ""
		input.Placeholder = placeholder
		input.SetWidth(52)
		return input
	}
	m.recordInputs = []textinput.Model{
		newInput("Type: A, AAAA, CNAME, TXT, MX, CAA, NS, SRV"),
		newInput("Name: @, www, or full hostname"),
		newInput("Content / target"),
		newInput("TTL seconds; 0 means Auto"),
		newInput("Priority (MX/SRV only)"),
	}
	m.recordFocus = 0
	m.recordInputs[0].Focus()
	m.recordEditing = editing
	m.recordOriginalID = ""
	m.recordProxied = false
	if editing {
		records := m.filteredRecords()
		if len(records) > 0 {
			record := records[min(m.recordIndex, len(records)-1)]
			m.recordOriginalID = record.ID
			m.recordInputs[0].SetValue(string(record.Type))
			m.recordInputs[1].SetValue(record.Name)
			m.recordInputs[2].SetValue(displayRecordContent(record))
			m.recordInputs[3].SetValue(strconv.Itoa(record.TTL))
			if record.Priority != nil {
				m.recordInputs[4].SetValue(strconv.Itoa(int(*record.Priority)))
			}
			m.recordProxied = record.Proxied
		}
	} else {
		m.recordInputs[0].SetValue("A")
		m.recordInputs[3].SetValue("1")
	}
	m.editRecord = true
	m.err = nil
}

func (m *Model) updateRecordForm(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "esc":
			m.editRecord = false
			return m, nil
		case "ctrl+p":
			m.recordProxied = !m.recordProxied
			return m, nil
		case "tab", "down":
			m.focusRecord(1)
			return m, nil
		case "shift+tab", "up":
			m.focusRecord(-1)
			return m, nil
		case "enter":
			if m.recordFocus < len(m.recordInputs)-1 {
				m.focusRecord(1)
				return m, nil
			}
			record, err := m.recordFromForm()
			if err != nil {
				m.err = err
				return m, nil
			}
			m.editRecord = false
			m.confirmRecord = true
			m.recordDraft = record
			m.recordDraftEdit = m.recordEditing
			m.recordDraftID = m.recordOriginalID
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.recordInputs[m.recordFocus], cmd = m.recordInputs[m.recordFocus].Update(message)
	return m, cmd
}

func (m *Model) updateRecordConfirmation(message tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "esc", "n":
		m.confirmRecord = false
	case "y", "enter":
		zoneID := m.selectedZoneID()
		record, originalID, editing := m.recordDraft, m.recordDraftID, m.recordDraftEdit
		m.confirmRecord = false
		m.busy = true
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			var opErr error
			if editing {
				_, opErr = m.backend.PatchDNSRecord(ctx, zoneID, originalID, record)
			} else {
				_, opErr = m.backend.CreateDNSRecord(ctx, zoneID, record)
			}
			return operationMsg{message: "DNS record saved", err: opErr, reload: true}
		}
	}
	return m, nil
}

func (m *Model) focusRecord(delta int) {
	m.recordInputs[m.recordFocus].Blur()
	m.recordFocus = (m.recordFocus + delta + len(m.recordInputs)) % len(m.recordInputs)
	m.recordInputs[m.recordFocus].Focus()
}

func (m *Model) recordFromForm() (domain.DNSRecord, error) {
	typeValue := domain.RecordType(strings.ToUpper(strings.TrimSpace(m.recordInputs[0].Value())))
	if !typeValue.Editable() {
		return domain.DNSRecord{}, fmt.Errorf("unsupported editable record type %q", typeValue)
	}
	ttl, err := strconv.Atoi(strings.TrimSpace(m.recordInputs[3].Value()))
	if err != nil || ttl < 0 {
		return domain.DNSRecord{}, errors.New("TTL must be a non-negative number")
	}
	var priority *uint16
	if value := strings.TrimSpace(m.recordInputs[4].Value()); value != "" {
		parsed, parseErr := strconv.ParseUint(value, 10, 16)
		if parseErr != nil {
			return domain.DNSRecord{}, errors.New("priority must be between 0 and 65535")
		}
		v := uint16(parsed)
		priority = &v
	}
	record := domain.DNSRecord{
		Type: typeValue, Name: strings.TrimSpace(m.recordInputs[1].Value()),
		Content: m.recordInputs[2].Value(), TTL: ttl, Priority: priority, Proxied: m.recordProxied,
	}
	if typeValue == domain.RecordCAA {
		parts := strings.Fields(record.Content)
		if len(parts) < 3 {
			return domain.DNSRecord{}, errors.New("CAA content must be: flags tag value")
		}
		flags, parseErr := strconv.ParseUint(parts[0], 10, 8)
		if parseErr != nil {
			return domain.DNSRecord{}, errors.New("CAA flags must be between 0 and 255")
		}
		value := strings.Join(parts[2:], " ")
		if unquoted, unquoteErr := strconv.Unquote(value); unquoteErr == nil {
			value = unquoted
		}
		record.Data, _ = json.Marshal(map[string]any{"flags": flags, "tag": parts[1], "value": value})
	}
	if typeValue == domain.RecordSRV {
		parts := strings.Fields(record.Content)
		if len(parts) != 3 && len(parts) != 4 {
			return domain.DNSRecord{}, errors.New("SRV content must be: [priority] weight port target")
		}
		start := 0
		if len(parts) == 4 {
			parsed, parseErr := strconv.ParseUint(parts[0], 10, 16)
			if parseErr != nil {
				return domain.DNSRecord{}, errors.New("SRV priority must be between 0 and 65535")
			}
			value := uint16(parsed)
			record.Priority = &value
			start = 1
		} else if record.Priority == nil {
			return domain.DNSRecord{}, errors.New("SRV priority is required")
		}
		weight, weightErr := strconv.ParseUint(parts[start], 10, 16)
		port, portErr := strconv.ParseUint(parts[start+1], 10, 16)
		if weightErr != nil || portErr != nil {
			return domain.DNSRecord{}, errors.New("SRV weight and port must be between 0 and 65535")
		}
		record.Data, _ = json.Marshal(map[string]any{"priority": *record.Priority, "weight": weight, "port": port, "target": parts[start+2]})
	}
	return record, nil
}

func displayRecordContent(record domain.DNSRecord) string {
	if len(record.Data) > 0 && string(record.Data) != "null" {
		switch record.Type {
		case domain.RecordCAA:
			var data struct {
				Flags uint8  `json:"flags"`
				Tag   string `json:"tag"`
				Value string `json:"value"`
			}
			if json.Unmarshal(record.Data, &data) == nil && data.Tag != "" {
				return fmt.Sprintf("%d %s %s", data.Flags, data.Tag, data.Value)
			}
		case domain.RecordSRV:
			var data struct {
				Priority uint16 `json:"priority"`
				Weight   uint16 `json:"weight"`
				Port     uint16 `json:"port"`
				Target   string `json:"target"`
			}
			if json.Unmarshal(record.Data, &data) == nil && data.Target != "" {
				priority := data.Priority
				if record.Priority != nil {
					priority = *record.Priority
				}
				return fmt.Sprintf("%d %d %d %s", priority, data.Weight, data.Port, data.Target)
			}
		}
	}
	return record.Content
}

func (m *Model) updateDeleteConfirmation(message tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "esc", "n":
		m.confirmDelete = false
	case "y", "enter":
		records := m.filteredRecords()
		if len(records) == 0 {
			m.confirmDelete = false
			return m, nil
		}
		record := records[min(m.recordIndex, len(records)-1)]
		zoneID := m.selectedZoneID()
		m.confirmDelete = false
		m.busy = true
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			err := m.backend.DeleteDNSRecord(ctx, zoneID, record.ID)
			return operationMsg{message: "DNS record deleted", err: err, reload: true}
		}
	}
	return m, nil
}

func (m *Model) updateTLSConfirmation(message tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "esc", "n":
		m.confirmTLS = false
		m.confirmTLSZoneID = ""
	case "y", "enter":
		zoneID := m.selectedZoneID()
		if !m.tlsSnapshotReadyForSelectedZone() || zoneID != m.confirmTLSZoneID {
			m.confirmTLS = false
			m.confirmTLSZoneID = ""
			m.toast, m.toastAt = "TLS snapshot changed; reload the selected zone before applying", time.Now()
			return m, nil
		}
		draft := m.tlsDraft
		m.confirmTLS = false
		m.confirmTLSZoneID = ""
		m.busy = true
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			_, err := m.backend.UpdateTLSSettings(ctx, zoneID, draft)
			return operationMsg{message: "Cloudflare TLS settings updated", err: err, reload: true}
		}
	}
	return m, nil
}

func (m *Model) openCertificateForm(action string) {
	newInput := func(placeholder string) textinput.Model {
		input := textinput.New()
		input.Prompt = ""
		input.Placeholder = placeholder
		input.SetWidth(54)
		return input
	}
	m.certificateAction = action
	m.certificateFocus = 0
	m.certificateAcceptTerms = false
	m.certificateConfirmProduction = false
	m.certificateIssueZoneID = ""
	m.certificateIssueZoneValue = ""
	m.certificateLineageID = ""
	m.certificateExpectedName = ""
	switch action {
	case "issue":
		zone := ""
		if selected, ok := m.selectedZone(); ok {
			zone = selected.ID
			m.certificateIssueZoneID = selected.ID
			m.certificateIssueZoneValue = selected.ID
		}
		m.certificateInputs = []textinput.Model{
			newInput("Comma-separated zone names"),
			newInput("staging or production"),
			newInput("Let’s Encrypt contact email"),
			newInput("Nested labels, optional"),
			newInput("EC256 or RSA2048"),
		}
		m.certificateInputs[0].SetValue(zone)
		m.certificateInputs[1].SetValue("staging")
		m.certificateInputs[4].SetValue(string(domain.KeyECDSAP256))
	case "import":
		m.certificateInputs = []textinput.Model{
			newInput("Path to certificate/fullchain PEM"),
			newInput("Display name, optional"),
			newInput("Zone name, optional"),
		}
	case "export":
		m.certificateInputs = []textinput.Model{newInput("Destination directory")}
	case "revoke":
		lineages := m.filteredLineages()
		environment := "production"
		if len(lineages) > 0 {
			lineage := lineages[min(m.rowOffset, len(lineages)-1)]
			m.certificateLineageID = lineage.ID
			m.certificateExpectedName = lineage.Name
			if item := m.certificateItem(lineage.ID); item.Environment == "staging" || item.Environment == "production" {
				environment = item.Environment
			}
		}
		m.certificateInputs = []textinput.Model{
			newInput("staging or production"),
			newInput("Type the exact lineage name"),
			newInput("RFC 5280 reason code, optional"),
		}
		m.certificateInputs[0].SetValue(environment)
	case "renew":
		environment := "production"
		lineages := m.filteredLineages()
		if len(lineages) > 0 {
			if item := m.certificateItem(lineages[min(m.rowOffset, len(lineages)-1)].ID); item.Environment == "staging" || item.Environment == "production" {
				environment = item.Environment
			}
		}
		m.certificateInputs = []textinput.Model{newInput("staging or production")}
		m.certificateInputs[0].SetValue(environment)
	}
	if len(m.certificateInputs) > 0 {
		m.certificateInputs[0].Focus()
	}
	m.err = nil
}

func (m *Model) updateCertificateForm(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "esc":
			m.certificateAction = ""
			return m, nil
		case "ctrl+t":
			if m.certificateAction == "issue" {
				m.certificateAcceptTerms = !m.certificateAcceptTerms
			}
			return m, nil
		case "ctrl+p":
			if m.certificateAction == "issue" || m.certificateAction == "renew" {
				m.certificateConfirmProduction = !m.certificateConfirmProduction
			}
			return m, nil
		case "tab", "down":
			m.focusCertificate(1)
			return m, nil
		case "shift+tab", "up":
			m.focusCertificate(-1)
			return m, nil
		case "enter":
			if m.certificateFocus < len(m.certificateInputs)-1 {
				m.focusCertificate(1)
				return m, nil
			}
			return m, m.submitCertificateForm()
		}
	}
	var cmd tea.Cmd
	m.certificateInputs[m.certificateFocus], cmd = m.certificateInputs[m.certificateFocus].Update(message)
	return m, cmd
}

func (m *Model) focusCertificate(delta int) {
	m.certificateInputs[m.certificateFocus].Blur()
	m.certificateFocus = (m.certificateFocus + delta + len(m.certificateInputs)) % len(m.certificateInputs)
	m.certificateInputs[m.certificateFocus].Focus()
}

func (m *Model) submitCertificateForm() tea.Cmd {
	action := m.certificateAction
	inputs := make([]string, len(m.certificateInputs))
	for i := range m.certificateInputs {
		inputs[i] = strings.TrimSpace(m.certificateInputs[i].Value())
	}
	if action == "export" && (len(inputs) == 0 || inputs[0] == "") {
		m.err = errors.New("an explicit export destination is required")
		return nil
	}
	if action == "revoke" {
		if m.certificateLineageID == "" || m.certificateExpectedName == "" {
			m.err = errors.New("the selected certificate lineage is no longer available")
			return nil
		}
		if inputs[1] != m.certificateExpectedName {
			m.err = fmt.Errorf("type %q exactly to confirm revocation", m.certificateExpectedName)
			return nil
		}
	}
	m.certificateAction = ""
	m.busy = true
	switch action {
	case "issue":
		zoneIDs, err := m.resolveIssueZoneValues(strings.Split(inputs[0], ","))
		if err != nil {
			m.busy = false
			m.err = err
			return nil
		}
		request := app.IssueZonesRequest{
			ZoneIDs: zoneIDs, Environment: strings.ToLower(inputs[1]), Email: inputs[2],
			NestedNames: splitComma(inputs[3]), AcceptTerms: m.certificateAcceptTerms,
			ConfirmProduction: m.certificateConfirmProduction,
			KeyAlgorithm:      domain.KeyAlgorithm(strings.ToUpper(inputs[4])),
		}
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
			defer cancel()
			result, issueErr := m.backend.IssueCertificates(ctx, request)
			message := fmt.Sprintf("Issued %d certificate(s)", len(result.Completed))
			if warnings := result.WarningCount(); warnings > 0 {
				message += fmt.Sprintf(" with %d activation warning(s)", warnings)
			}
			return operationMsg{message: message, err: issueErr, reload: true}
		}
	case "import":
		zoneID := ""
		if inputs[2] != "" {
			ids, err := m.resolveZoneValues([]string{inputs[2]})
			if err != nil {
				m.busy = false
				m.err = err
				return nil
			}
			zoneID = ids[0]
		}
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			lineage, _, importErr := m.backend.ImportCertificateMetadata(ctx, inputs[0], inputs[1], zoneID)
			return operationMsg{message: "Imported certificate metadata for " + lineage.Name, err: importErr, reload: true}
		}
	case "export":
		lineages := m.filteredLineages()
		if len(lineages) == 0 {
			m.busy = false
			return nil
		}
		lineage := lineages[min(m.rowOffset, len(lineages)-1)]
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			path, exportErr := m.backend.ExportCertificate(ctx, lineage.ID, inputs[0])
			return operationMsg{message: "Exported certificate to " + path, err: exportErr, reload: true}
		}
	case "revoke":
		lineageID := m.certificateLineageID
		var reason *uint
		if inputs[2] != "" {
			parsed, err := strconv.ParseUint(inputs[2], 10, 32)
			if err != nil {
				m.busy = false
				m.certificateAction = "revoke"
				m.err = errors.New("revocation reason must be a number")
				return nil
			}
			value := uint(parsed)
			reason = &value
		}
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			revokeErr := m.backend.RevokeCertificate(ctx, lineageID, strings.ToLower(inputs[0]), inputs[1], reason)
			return operationMsg{message: "Certificate revoked", err: revokeErr, reload: true}
		}
	case "renew":
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
			defer cancel()
			result, renewErr := m.backend.RenewCertificates(ctx, strings.ToLower(inputs[0]), m.certificateConfirmProduction)
			message := fmt.Sprintf("Renewed %d certificate(s)", len(result.Completed))
			if warnings := result.WarningCount(); warnings > 0 {
				message += fmt.Sprintf(" with %d activation warning(s)", warnings)
			}
			return operationMsg{message: message, err: renewErr, reload: true}
		}
	}
	m.busy = false
	return nil
}

func (m *Model) resolveZoneValues(values []string) ([]string, error) {
	byID := make(map[string]string, len(m.zones))
	byName := make(map[string][]string, len(m.zones))
	for _, zone := range m.zones {
		byID[strings.ToLower(zone.ID)] = zone.ID
		name := strings.ToLower(strings.TrimSpace(zone.Name))
		matches := byName[name]
		if !containsString(matches, zone.ID) {
			byName[name] = append(matches, zone.ID)
		}
	}
	var result []string
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		id, ok := byID[key]
		if !ok {
			matches := byName[key]
			switch len(matches) {
			case 0:
				return nil, fmt.Errorf("zone %q is not synchronized", value)
			case 1:
				id = matches[0]
			default:
				return nil, fmt.Errorf("zone name %q is ambiguous across %d synchronized zones; use the local zone ID", value, len(matches))
			}
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	if len(result) == 0 {
		return nil, errors.New("at least one synchronized zone is required")
	}
	return result, nil
}

func (m *Model) resolveIssueZoneValues(values []string) ([]string, error) {
	resolved := make([]string, 0, len(values))
	usedSelected := false
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if !usedSelected && m.certificateIssueZoneID != "" && strings.EqualFold(value, m.certificateIssueZoneValue) && m.hasZoneID(m.certificateIssueZoneID) {
			resolved = append(resolved, m.certificateIssueZoneID)
			usedSelected = true
			continue
		}
		ids, err := m.resolveZoneValues([]string{value})
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, ids[0])
	}
	return m.resolveZoneValues(resolved)
}

func (m *Model) hasZoneID(zoneID string) bool {
	_, ok := m.zoneByID(zoneID)
	return ok
}

func (m *Model) zoneByID(zoneID string) (domain.Zone, bool) {
	for _, zone := range m.zones {
		if zone.ID == zoneID {
			return zone, true
		}
	}
	return domain.Zone{}, false
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (m *Model) isMutationKey(key string) bool {
	switch key {
	case "r":
		return true
	case "a":
		return m.screen == screenDashboard || m.screen == screenAccounts
	case "n":
		return m.screen == screenDNS || m.screen == screenCertificates
	case "i", "x", "u":
		return m.screen == screenCertificates
	case "d":
		return m.screen == screenDNS || m.screen == screenCertificates
	case "e":
		return m.screen == screenDNS
	case "s", "m", "t", "v", "h":
		return m.screen == screenTLS
	default:
		return false
	}
}

func splitComma(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func (m *Model) updateSearch(message tea.Msg) (tea.Model, tea.Cmd) {
	beforeTLSZone := m.activeTLSZoneID
	if key, ok := message.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "esc", "enter":
			m.searching = false
			m.searchInput.Blur()
			m.clampSelection()
			return m, m.reloadTLSAfterFilterChange(beforeTLSZone)
		}
	}
	var cmd tea.Cmd
	m.searchInput, cmd = m.searchInput.Update(message)
	m.clampSelection()
	if reload := m.reloadTLSAfterFilterChange(beforeTLSZone); reload != nil {
		return m, reload
	}
	return m, cmd
}

func (m *Model) reloadTLSAfterFilterChange(previousZoneID string) tea.Cmd {
	if m.screen != screenTLS {
		return nil
	}
	zones := m.filteredZones()
	if len(zones) == 0 {
		// A TLS filter may target an edge-certificate field rather than a zone.
		// Keep the active zone stable so matching certificate rows remain visible.
		return nil
	}
	for index, zone := range zones {
		if zone.ID == m.activeTLSZoneID {
			m.zoneIndex = index
			return nil
		}
	}
	m.zoneIndex = 0
	m.activeTLSZoneID = zones[0].ID
	if m.activeTLSZoneID == previousZoneID {
		return nil
	}
	return m.startLoad(m.activeTLSZoneID, true, false)
}

func (m *Model) updateOverlay(message tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	if m.showHelp {
		if key.String() == "esc" || key.String() == "?" || key.String() == "enter" {
			m.showHelp = false
		}
		return m, nil
	}
	commands := paletteCommands()
	switch key.String() {
	case "esc", "ctrl+k":
		m.showPalette = false
	case "up", "k":
		m.paletteIndex = (m.paletteIndex - 1 + len(commands)) % len(commands)
	case "down", "j":
		m.paletteIndex = (m.paletteIndex + 1) % len(commands)
	case "enter":
		selected := m.paletteIndex
		m.showPalette = false
		if selected < len(screens) {
			return m, m.navigateToScreen(screen(selected))
		}
		if m.recoveryBlocked {
			m.toast, m.toastAt = "Crash recovery must succeed before mutations are enabled", time.Now()
			return m, nil
		}
		if m.busy || m.loading {
			message := "An operation is already running"
			if !m.busy {
				message = "Loading the latest zone state"
			}
			m.toast, m.toastAt = message, time.Now()
			return m, nil
		}
		if selected == len(screens) {
			m.openCredentialForm()
			return m, textinput.Blink
		}
		m.busy = true
		return m, syncCmd(m.backend)
	}
	return m, nil
}

func dashboardRecoveryBlocked(snapshot domain.DashboardSnapshot) bool {
	for _, issue := range snapshot.Issues {
		if issue.Kind == "certificate_commit_recovery_failed" || issue.ResourceID == "certificate-commit-recovery" {
			return true
		}
	}
	return false
}

func (m *Model) moveSelection(delta int) {
	switch m.screen {
	case screenZones, screenDNS, screenTLS:
		if m.screen == screenDNS {
			items := len(m.filteredRecords())
			if items > 0 {
				m.recordIndex = clamp(m.recordIndex+delta, 0, items-1)
			}
			return
		}
		zones := m.filteredZones()
		items := len(zones)
		if items > 0 {
			if m.screen == screenTLS {
				for index, zone := range zones {
					if zone.ID == m.activeTLSZoneID {
						m.zoneIndex = index
						break
					}
				}
			}
			m.zoneIndex = clamp(m.zoneIndex+delta, 0, items-1)
			if m.screen == screenTLS {
				m.activeTLSZoneID = zones[m.zoneIndex].ID
			}
		}
	case screenAccounts:
		items := len(m.filteredCredentials())
		if items > 0 {
			m.rowOffset = clamp(m.rowOffset+delta, 0, items-1)
		}
	case screenCertificates:
		items := len(m.filteredLineages())
		if items > 0 {
			m.rowOffset = clamp(m.rowOffset+delta, 0, items-1)
		}
	case screenActivity:
		jobs := m.filteredJobs()
		if len(jobs) > 0 {
			m.rowOffset = clamp(m.rowOffset+delta, 0, len(jobs)-1)
		}
	}
}

func (m *Model) selectedZoneID() string {
	if m.screen == screenDNS && m.activeDNSZoneID != "" {
		return m.activeDNSZoneID
	}
	if m.screen == screenTLS && m.activeTLSZoneID != "" {
		return m.activeTLSZoneID
	}
	if m.screen != screenZones {
		if len(m.zones) == 0 {
			return ""
		}
		return m.zones[min(m.zoneIndex, len(m.zones)-1)].ID
	}
	zones := m.filteredZones()
	if len(zones) == 0 {
		return ""
	}
	return zones[min(m.zoneIndex, len(zones)-1)].ID
}

func (m *Model) selectedZone() (domain.Zone, bool) {
	if m.screen == screenDNS && m.activeDNSZoneID != "" {
		for _, zone := range m.zones {
			if zone.ID == m.activeDNSZoneID {
				return zone, true
			}
		}
		return domain.Zone{}, false
	}
	if m.screen == screenTLS && m.activeTLSZoneID != "" {
		for _, zone := range m.zones {
			if zone.ID == m.activeTLSZoneID {
				return zone, true
			}
		}
		return domain.Zone{}, false
	}
	if m.screen != screenZones && m.screen != screenDNS && m.screen != screenTLS {
		if len(m.zones) == 0 {
			return domain.Zone{}, false
		}
		return m.zones[min(m.zoneIndex, len(m.zones)-1)], true
	}
	zones := m.filteredZones()
	if len(zones) == 0 {
		return domain.Zone{}, false
	}
	return zones[min(m.zoneIndex, len(zones)-1)], true
}

func (m *Model) filterValue() string {
	return strings.ToLower(strings.TrimSpace(m.searchInput.Value()))
}

func (m *Model) filteredZones() []domain.Zone {
	query := m.filterValue()
	if query == "" {
		return m.zones
	}
	result := make([]domain.Zone, 0)
	for _, value := range m.zones {
		searchable := strings.Join([]string{value.ID, value.Name, value.UnicodeName, string(value.Status), value.Plan, value.AccountID, m.accountLabel(value.AccountID), value.PreferredCredentialID, m.credentialLabel(value.PreferredCredentialID)}, " ")
		if strings.Contains(strings.ToLower(searchable), query) {
			result = append(result, value)
		}
	}
	return result
}

func (m *Model) filteredRecords() []domain.DNSRecord {
	query := m.filterValue()
	if query == "" {
		return m.records
	}
	result := make([]domain.DNSRecord, 0)
	for _, value := range m.records {
		if strings.Contains(strings.ToLower(string(value.Type)+" "+value.Name+" "+displayRecordContent(value)), query) {
			result = append(result, value)
		}
	}
	return result
}

func (m *Model) filteredCredentials() []domain.Credential {
	query := m.filterValue()
	if query == "" {
		return m.credentials
	}
	result := make([]domain.Credential, 0)
	for _, value := range m.credentials {
		searchable := strings.Join([]string{value.ID, value.Label, value.Provider, string(value.Kind), value.AccountHint, string(value.Status), strings.Join(value.Capabilities, " ")}, " ")
		if strings.Contains(strings.ToLower(searchable), query) {
			result = append(result, value)
		}
	}
	return result
}

func (m *Model) filteredLineages() []domain.CertificateLineage {
	query := m.filterValue()
	if query == "" {
		return m.lineages
	}
	result := make([]domain.CertificateLineage, 0)
	for _, value := range m.lineages {
		item := m.certificateItem(value.ID)
		issuer := ""
		if item.Current != nil {
			issuer = item.Current.Issuer
		}
		searchable := strings.Join([]string{value.ID, value.Name, item.Environment, item.Status, issuer, strings.Join(value.Identifiers, " ")}, " ")
		if strings.Contains(strings.ToLower(searchable), query) {
			result = append(result, value)
		}
	}
	return result
}

func (m *Model) filteredJobs() []domain.Job {
	query := m.filterValue()
	if query == "" {
		return m.jobs
	}
	result := make([]domain.Job, 0)
	for _, value := range m.jobs {
		searchable := strings.Join([]string{value.ID, string(value.State), value.Kind, value.ResourceID, value.Message, value.Error}, " ")
		if strings.Contains(strings.ToLower(searchable), query) {
			result = append(result, value)
		}
	}
	return result
}

func (m *Model) filteredAudit() []domain.AuditEvent {
	query := m.filterValue()
	if query == "" {
		return m.audit
	}
	result := make([]domain.AuditEvent, 0)
	for _, value := range m.audit {
		searchable := value.Action + " " + value.ResourceID + " " + string(value.Before) + " " + string(value.After)
		if strings.Contains(strings.ToLower(searchable), query) {
			result = append(result, value)
		}
	}
	return result
}

func (m *Model) filteredEdgeCertificates() []domain.EdgeCertificate {
	query := m.filterValue()
	if query == "" {
		return m.edgeCertificates
	}
	result := make([]domain.EdgeCertificate, 0)
	for _, value := range m.edgeCertificates {
		searchable := value.ID + " " + value.Type + " " + value.Status + " " + strings.Join(value.Hosts, " ")
		if strings.Contains(strings.ToLower(searchable), query) {
			result = append(result, value)
		}
	}
	return result
}

func (m *Model) clampSelection() {
	m.zoneIndex = clamp(m.zoneIndex, 0, max(0, len(m.filteredZones())-1))
	m.recordIndex = clamp(m.recordIndex, 0, max(0, len(m.filteredRecords())-1))
	switch m.screen {
	case screenAccounts:
		m.rowOffset = clamp(m.rowOffset, 0, max(0, len(m.filteredCredentials())-1))
	case screenCertificates:
		m.rowOffset = clamp(m.rowOffset, 0, max(0, len(m.filteredLineages())-1))
	case screenActivity:
		m.rowOffset = clamp(m.rowOffset, 0, max(0, len(m.filteredJobs())-1))
	}
}

func (m *Model) resizeInputs() {
	width := clamp(m.width-16, 28, 60)
	m.searchInput.SetWidth(width)
	for i := range m.unlockInputs {
		m.unlockInputs[i].SetWidth(width)
	}
	for i := range m.credentialInputs {
		m.credentialInputs[i].SetWidth(width)
	}
	for i := range m.recordInputs {
		m.recordInputs[i].SetWidth(width)
	}
	for i := range m.certificateInputs {
		m.certificateInputs[i].SetWidth(width)
	}
}

func nextValue(current string, values []string) string {
	for i, value := range values {
		if value == current {
			return values[(i+1)%len(values)]
		}
	}
	return values[0]
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func paletteCommands() []string {
	result := make([]string, 0, len(screens)+2)
	for _, item := range screens {
		result = append(result, "Go to "+item.name)
	}
	return append(result, "Add Cloudflare account", "Synchronize everything")
}
