package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/MeghdadFadaee/domainops/internal/app"
	"github.com/MeghdadFadaee/domainops/internal/domain"
)

func (m *Model) render() string {
	if m.terminalUndersized() {
		message := m.theme.modal.Width(min(52, max(20, m.width-4))).Render(
			m.theme.brand.Render("DOMAINOPS") + "\n\n" +
				"The terminal is too small for a safe operator view.\n" +
				m.theme.mutedText.Render(fmt.Sprintf("Current %d×%d · minimum 64×18", m.width, m.height)),
		)
		return m.theme.app.Width(m.width).Height(m.height).Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, message))
	}
	if m.unlock {
		return m.renderUnlock()
	}
	if m.addCredential {
		return m.renderCredentialForm()
	}
	if m.editRecord {
		return m.renderRecordForm()
	}
	if m.certificateAction != "" {
		return m.renderCertificateForm()
	}
	if m.confirmRecord {
		return m.renderRecordConfirmation()
	}
	if m.confirmDelete {
		return m.renderDeleteConfirmation()
	}
	if m.confirmTLS {
		return m.renderTLSConfirmation()
	}
	if m.showHelp {
		return m.renderHelp()
	}
	if m.showPalette {
		return m.renderPalette()
	}

	header := m.renderHeader()
	foot := m.renderFooter()
	bodyHeight := max(1, m.height-lipgloss.Height(header)-lipgloss.Height(foot))
	sidebarWidth := 23
	if m.width < 88 {
		sidebarWidth = 15
	}
	mainWidth := max(20, m.width-sidebarWidth)
	sidebar := m.renderSidebar(sidebarWidth, bodyHeight)
	main := m.theme.app.Width(mainWidth).Height(bodyHeight).Padding(1, 1).Render(m.renderScreen(mainWidth-2, bodyHeight-2))
	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, main)
	return m.theme.app.Width(m.width).Height(m.height).Render(header + "\n" + body + "\n" + foot)
}

func (m *Model) renderHeader() string {
	brand := m.theme.brand.Render("◆ DOMAINOPS")
	section := m.theme.mutedText.Render("  /  " + screens[m.screen].name)
	left := brand + section
	state := m.theme.statusOK.Render("● READY")
	if m.busy || m.loading {
		state = m.theme.statusWarn.Render("◌ WORKING")
	} else if m.err != nil {
		state = m.theme.statusBad.Render("● ATTENTION")
	}
	version := m.options.Version
	if version == "" {
		version = "dev"
	}
	right := m.theme.mutedText.Render(version) + "  " + state
	space := strings.Repeat(" ", max(1, m.width-lipgloss.Width(left)-lipgloss.Width(right)-4))
	return m.theme.header.Width(m.width).Render(left + space + right)
}

func (m *Model) renderFooter() string {
	left := m.theme.key.Render("?") + " help  " + m.theme.key.Render("Ctrl+K") + " commands  " + m.theme.key.Render("/") + " filter"
	right := m.theme.key.Render("r") + " sync  " + m.theme.key.Render("q") + " quit"
	if m.recoveryBlocked {
		right = m.theme.key.Render("R") + " retry recovery  " + m.theme.key.Render("q") + " quit"
	}
	if m.searching {
		left = m.searchInput.View()
	} else if m.filterValue() != "" {
		left = m.theme.statusWarn.Render("FILTER: ") + m.searchInput.Value() + "  " + m.theme.mutedText.Render("/ to edit")
	}
	if m.err != nil {
		left = m.theme.statusBad.Render("! ") + truncate(m.err.Error(), max(16, m.width-lipgloss.Width(right)-8))
	} else if m.toast != "" && time.Since(m.toastAt) < 12*time.Second {
		left = m.theme.statusOK.Render("✓ ") + m.toast
	}
	space := strings.Repeat(" ", max(1, m.width-lipgloss.Width(left)-lipgloss.Width(right)-2))
	return m.theme.header.Width(m.width).Render(left + space + right)
}

func (m *Model) renderSidebar(width, height int) string {
	var lines []string
	for i, item := range screens {
		label := fmt.Sprintf("%d  %s %s", i+1, item.icon, item.name)
		if width < 18 {
			label = fmt.Sprintf("%d %s %s", i+1, item.icon, truncate(item.name, 7))
		}
		style := m.theme.nav.Width(width - 3)
		if screen(i) == m.screen {
			style = m.theme.navActive.Width(width - 3)
		}
		lines = append(lines, style.Render(label))
	}
	lines = append(lines, "", m.theme.mutedText.Render("WORKSPACE"))
	if zone, ok := m.selectedZone(); ok {
		lines = append(lines, m.theme.panelTitle.Render(truncate(zone.Name, width-4)), m.theme.mutedText.Render(strings.ToUpper(string(zone.Status))))
	} else {
		lines = append(lines, m.theme.mutedText.Render("No zone selected"))
	}
	return m.theme.sidebar.Width(width).Height(height).Render(strings.Join(lines, "\n"))
}

func (m *Model) renderScreen(width, height int) string {
	if m.loading && len(m.zones) == 0 && m.screen != screenDashboard {
		return m.emptyState("Synchronizing local state…", "The view will update without blocking the terminal.", width, height)
	}
	switch m.screen {
	case screenDashboard:
		return m.renderDashboard(width, height)
	case screenAccounts:
		return m.renderAccounts(width, height)
	case screenZones:
		return m.renderZones(width, height)
	case screenDNS:
		return m.renderDNS(width, height)
	case screenCertificates:
		return m.renderCertificates(width, height)
	case screenTLS:
		return m.renderTLS(width, height)
	case screenActivity:
		return m.renderActivity(width, height)
	default:
		return ""
	}
}

func (m *Model) renderDashboard(width, height int) string {
	if len(m.credentials) == 0 {
		body := m.theme.brand.Render("Welcome to DomainOps") + "\n\n" +
			"Connect a scoped Cloudflare API token to build your live domain inventory.\n" +
			m.theme.mutedText.Render("Recommended scopes: Zone Read, DNS Read/Write, and optional Zone Settings Read/Write.") + "\n\n" +
			m.theme.key.Render("a") + "  Add your first Cloudflare account"
		return m.panel("GET STARTED", body, width, min(height, 12))
	}
	cardGap := 1
	columns := 3
	if width < 78 {
		columns = 2
	}
	cardWidth := max(15, (width-(columns-1)*cardGap)/columns)
	cards := []string{
		m.statCard("ACCOUNTS", m.dashboard.Accounts, "connected", cardWidth),
		m.statCard("ZONES", m.dashboard.Zones, "managed", cardWidth),
		m.statCard("DNS RECORDS", m.dashboard.DNSRecords, "cached", cardWidth),
		m.statCard("CERTIFICATES", m.dashboard.Certificates, "tracked", cardWidth),
		m.statCard("RENEWAL DUE", m.dashboard.CertificatesDue, "action needed", cardWidth),
		m.statCard("EXPIRED", m.dashboard.CertificatesExpired, "critical", cardWidth),
		m.statCard("ACTIVE JOBS", m.dashboard.ActiveJobs, "background", cardWidth),
	}
	var rows []string
	for i := 0; i < len(cards); i += columns {
		end := min(i+columns, len(cards))
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, intersperse(cards[i:end], strings.Repeat(" ", cardGap))...))
	}
	stats := strings.Join(rows, "\n")
	remaining := max(6, height-lipgloss.Height(stats)-1)
	issues := m.renderIssues(width, remaining)
	return stats + "\n" + issues
}

func (m *Model) statCard(label string, value int, note string, width int) string {
	valueStyle := m.theme.brand.Copy().Bold(true)
	body := m.theme.mutedText.Render(label) + "\n" + valueStyle.Render(fmt.Sprintf("%d", value)) + "  " + m.theme.mutedText.Render(note)
	return m.theme.panel.Width(width - 2).Height(3).Render(body)
}

func (m *Model) renderIssues(width, height int) string {
	issues := append([]domain.HealthIssue(nil), m.dashboard.Issues...)
	sort.SliceStable(issues, func(i, j int) bool { return severityRank(issues[i].Severity) > severityRank(issues[j].Severity) })
	var rows []string
	limit := max(1, height-3)
	for i, issue := range issues {
		if i >= limit {
			break
		}
		marker := m.theme.mutedText.Render("●")
		switch issue.Severity {
		case domain.SeverityCritical:
			marker = m.theme.statusBad.Render("●")
		case domain.SeverityWarning:
			marker = m.theme.statusWarn.Render("●")
		default:
			marker = m.theme.statusOK.Render("●")
		}
		rows = append(rows, marker+"  "+truncate(issue.Title, width-10)+"  "+m.theme.mutedText.Render(truncate(issue.Detail, max(0, width-len(issue.Title)-16))))
	}
	if len(rows) == 0 {
		rows = []string{m.theme.statusOK.Render("✓ No urgent findings"), m.theme.mutedText.Render("Run a sync to refresh DNS and public certificate observations.")}
	}
	return m.panel("ACTION QUEUE", strings.Join(rows, "\n"), width, height)
}

func (m *Model) renderAccounts(width, height int) string {
	values := m.filteredCredentials()
	if len(values) == 0 {
		return m.emptyState("No Cloudflare accounts", "Press a to add a scoped API token.", width, height)
	}
	header := row(width, []cell{{"LABEL", 28}, {"TOKEN", 18}, {"STATUS", 14}, {"CAPABILITIES", 40}})
	rows := []string{m.theme.mutedText.Render(header)}
	reserved := 0
	if len(m.accounts) > 0 {
		reserved = 4
	}
	limit := max(1, height-4-reserved)
	start := viewportStart(m.rowOffset, limit, len(values))
	for i := start; i < len(values) && i < start+limit; i++ {
		value := values[i]
		status := string(value.Status)
		line := row(width, []cell{{value.Label, 28}, {string(value.Kind), 18}, {status, 14}, {strings.Join(value.Capabilities, ", "), 40}})
		if i == m.rowOffset {
			line = m.theme.selected.Width(width - 2).Render(line)
		}
		rows = append(rows, line)
	}
	if len(m.accounts) > 0 {
		names := make([]string, 0, len(m.accounts))
		for _, account := range m.accounts {
			names = append(names, account.Name)
		}
		rows = append(rows, "", m.theme.panelTitle.Render(fmt.Sprintf("REMOTE ACCOUNTS · %d", len(m.accounts))), m.theme.mutedText.Render(truncate(strings.Join(names, "  ·  "), max(1, width-6))))
	}
	return m.panel("CLOUDFLARE CONNECTIONS  ·  a add  ·  r sync", strings.Join(rows, "\n"), width, height)
}

func (m *Model) renderZones(width, height int) string {
	values := m.filteredZones()
	if len(values) == 0 {
		return m.emptyState("No zones found", "Add an account or synchronize Cloudflare.", width, height)
	}
	header := row(width, []cell{{"ZONE", 32}, {"ACCOUNT", 24}, {"CONNECTION", 22}, {"STATUS", 14}, {"PLAN", 14}})
	rows := []string{m.theme.mutedText.Render(header)}
	limit := max(1, height-4)
	start := viewportStart(m.zoneIndex, limit, len(values))
	for i := start; i < len(values) && i < start+limit; i++ {
		value := values[i]
		line := row(width, []cell{{value.Name, 32}, {m.accountLabel(value.AccountID), 24}, {m.credentialLabel(value.PreferredCredentialID), 22}, {string(value.Status), 14}, {value.Plan, 14}})
		if i == m.zoneIndex {
			line = m.theme.selected.Width(width - 2).Render(line)
		}
		rows = append(rows, line)
	}
	return m.panel("ZONES  ·  Enter open DNS  ·  j/k select", strings.Join(rows, "\n"), width, height)
}

func (m *Model) accountLabel(id string) string {
	for _, account := range m.accounts {
		if account.ID == id {
			return account.Name
		}
	}
	return id
}

func (m *Model) credentialLabel(id string) string {
	for _, credential := range m.credentials {
		if credential.ID == id {
			return credential.Label
		}
	}
	return id
}

func (m *Model) renderDNS(width, height int) string {
	zone, ok := m.selectedZone()
	if !ok {
		return m.emptyState("Select a zone", "Synchronize a Cloudflare account first.", width, height)
	}
	values := m.filteredRecords()
	if len(values) == 0 {
		return m.emptyState("No records in "+zone.Name, "Press n to create an A, AAAA, CNAME, TXT, MX, CAA, NS, or SRV record.", width, height)
	}
	header := row(width, []cell{{"TYPE", 8}, {"NAME", 34}, {"CONTENT", 42}, {"PROXY", 10}, {"TTL", 10}})
	rows := []string{m.theme.mutedText.Render(header)}
	limit := max(1, height-4)
	start := 0
	if m.recordIndex >= limit {
		start = m.recordIndex - limit + 1
	}
	for i := start; i < len(values) && i < start+limit; i++ {
		value := values[i]
		proxy := "DNS only"
		if value.Proxied {
			proxy = "proxied"
		}
		ttl := fmt.Sprintf("%ds", value.TTL)
		if value.TTL <= 1 {
			ttl = "Auto"
		}
		line := row(width, []cell{{string(value.Type), 8}, {value.Name, 34}, {displayRecordContent(value), 42}, {proxy, 10}, {ttl, 10}})
		if i == m.recordIndex {
			line = m.theme.selected.Width(width - 2).Render(line)
		}
		if !value.Type.Editable() || value.Managed {
			line = m.theme.mutedText.Render(line)
		}
		rows = append(rows, line)
	}
	title := fmt.Sprintf("DNS · %s  ·  n new  e edit  d delete  Ctrl+P proxy", zone.Name)
	return m.panel(title, strings.Join(rows, "\n"), width, height)
}

func (m *Model) renderCertificates(width, height int) string {
	values := m.filteredLineages()
	if len(values) == 0 {
		return m.emptyState("No certificates tracked", "Press n to issue a managed certificate or i to import PEM metadata.", width, height)
	}
	header := row(width, []cell{{"LINEAGE", 26}, {"ENV", 11}, {"STATUS", 11}, {"EXPIRES", 13}, {"ISSUER", 30}, {"IDENTIFIERS", 40}})
	rows := []string{m.theme.mutedText.Render(header)}
	limit := max(1, height-4)
	start := viewportStart(m.rowOffset, limit, len(values))
	for i := start; i < len(values) && i < start+limit; i++ {
		value := values[i]
		item := m.certificateItem(value.ID)
		expires, issuer := "—", "—"
		if item.Current != nil {
			expires = item.Current.NotAfter.Local().Format("2006-01-02")
			issuer = item.Current.Issuer
		}
		line := row(width, []cell{{value.Name, 26}, {item.Environment, 11}, {item.Status, 11}, {expires, 13}, {issuer, 30}, {strings.Join(value.Identifiers, ", "), 40}})
		if i == m.rowOffset {
			line = m.theme.selected.Width(width - 2).Render(line)
		}
		rows = append(rows, line)
	}
	return m.panel("CERTIFICATE INVENTORY  ·  n issue  u renew due  i import  x export  d revoke", strings.Join(rows, "\n"), width, height)
}

func (m *Model) certificateItem(lineageID string) app.CertificateInventoryItem {
	for _, item := range m.certificateItems {
		if item.Lineage.ID == lineageID {
			return item
		}
	}
	for _, lineage := range m.lineages {
		if lineage.ID == lineageID {
			return app.CertificateInventoryItem{Lineage: lineage, Environment: "unknown", Status: "unknown"}
		}
	}
	return app.CertificateInventoryItem{Environment: "unknown", Status: "unknown"}
}

func (m *Model) renderTLS(width, height int) string {
	zone, ok := m.selectedZone()
	if !ok {
		return m.emptyState("No zone selected", "Cloudflare TLS settings are zone-specific.", width, height)
	}
	if !m.tlsSnapshotReadyForSelectedZone() {
		detail := "A verified TLS snapshot has not loaded for this zone. Leave and reopen this view to retry."
		if m.loading {
			detail = "Loading a fresh, zone-bound Cloudflare TLS snapshot…"
		}
		return m.emptyState("TLS snapshot unavailable for "+zone.Name, detail, width, height)
	}
	value := func(enabled bool) string {
		if enabled {
			return m.theme.statusOK.Render("ENABLED")
		}
		return m.theme.mutedText.Render("DISABLED")
	}
	modeStyle := m.theme.statusOK
	if m.tlsDraft.Mode == "flexible" || m.tlsDraft.Mode == "off" {
		modeStyle = m.theme.statusWarn
	}
	body := m.theme.mutedText.Render("Cloudflare edge and origin controls are separate from your local Let’s Encrypt files.") + "\n" +
		m.theme.mutedText.Render("Verified for "+zone.Name+" · loaded "+m.tlsSnapshotAt.Local().Format("Jan 02 15:04:05")) + "\n\n" +
		row(width-8, []cell{{"Origin encryption mode", 34}, {modeStyle.Render(strings.ToUpper(m.tlsDraft.Mode)), 28}, {"m to cycle", 18}}) + "\n" +
		row(width-8, []cell{{"Always Use HTTPS", 34}, {value(m.tlsDraft.AlwaysUseHTTPS), 28}, {"h to toggle", 18}}) + "\n" +
		row(width-8, []cell{{"TLS 1.3", 34}, {value(m.tlsDraft.TLS13), 28}, {"t to toggle", 18}}) + "\n" +
		row(width-8, []cell{{"Minimum TLS", 34}, {m.tlsDraft.MinimumTLS, 28}, {"v to cycle", 22}}) + "\n\n" +
		m.theme.statusWarn.Render("Changes can interrupt proxied traffic. Review the diff, then press s to apply.")
	edgeCertificates := m.filteredEdgeCertificates()
	if len(edgeCertificates) > 0 {
		body += "\n\n" + m.theme.panelTitle.Render("EDGE CERTIFICATE PACKS")
		for _, certificate := range edgeCertificates {
			expiry := "managed by Cloudflare"
			if certificate.ExpiresAt != nil {
				expiry = certificate.ExpiresAt.Local().Format("2006-01-02")
			}
			body += "\n" + row(width-8, []cell{{certificate.Type, 20}, {certificate.Status, 16}, {strings.Join(certificate.Hosts, ", "), 44}, {expiry, 18}})
		}
	}
	return m.panel("CLOUDFLARE TLS · "+zone.Name, body, width, height)
}

func (m *Model) renderActivity(width, height int) string {
	jobs, audit := m.filteredJobs(), m.filteredAudit()
	if len(jobs) == 0 && len(audit) == 0 {
		return m.emptyState("No activity yet", "Synchronization and certificate jobs will appear here.", width, height)
	}
	header := row(width, []cell{{"STATE", 14}, {"KIND", 24}, {"PROGRESS", 12}, {"MESSAGE", 48}, {"UPDATED", 20}})
	rows := []string{m.theme.mutedText.Render(header)}
	limit := max(1, height-4)
	jobLimit := max(1, limit/2+1)
	start := viewportStart(m.rowOffset, jobLimit, len(jobs))
	for i := start; i < len(jobs) && i < start+jobLimit; i++ {
		value := jobs[i]
		line := row(width, []cell{{string(value.State), 14}, {value.Kind, 24}, {fmt.Sprintf("%d%%", value.Progress), 12}, {value.Message, 48}, {value.UpdatedAt.Local().Format("Jan 02 15:04"), 20}})
		if i == m.rowOffset {
			line = m.theme.selected.Width(width - 2).Render(line)
		}
		rows = append(rows, line)
	}
	if len(audit) > 0 {
		rows = append(rows, "", m.theme.panelTitle.Render("AUDIT TRAIL"), m.theme.mutedText.Render(row(width, []cell{{"TIME", 18}, {"ACTION", 24}, {"RESOURCE", 34}, {"CHANGE", 56}})))
		remaining := max(1, limit-len(rows)+2)
		for i, event := range audit {
			if i >= remaining {
				break
			}
			rows = append(rows, row(width, []cell{{event.CreatedAt.Local().Format("Jan 02 15:04"), 18}, {event.Action, 24}, {event.ResourceID, 34}, {auditChange(event), 56}}))
		}
	}
	return m.panel("DURABLE ACTIVITY & AUDIT", strings.Join(rows, "\n"), width, height)
}

func viewportStart(selected, limit, total int) int {
	if limit <= 0 || total <= limit {
		return 0
	}
	start := selected - limit + 1
	if start < 0 {
		start = 0
	}
	if start+limit > total {
		start = total - limit
	}
	return start
}

func auditChange(event domain.AuditEvent) string {
	compact := func(value []byte) string {
		if len(value) == 0 {
			return "∅"
		}
		var buffer bytes.Buffer
		if json.Compact(&buffer, value) == nil {
			return buffer.String()
		}
		return string(value)
	}
	return compact(event.Before) + " → " + compact(event.After)
}

func (m *Model) panel(title, body string, width, height int) string {
	if height < 3 {
		height = 3
	}
	return m.theme.panel.Width(max(8, width-2)).Height(max(1, height-2)).Render(m.theme.panelTitle.Render(title) + "\n" + body)
}

func (m *Model) emptyState(title, detail string, width, height int) string {
	body := m.theme.brand.Render(title) + "\n\n" + m.theme.mutedText.Render(detail)
	return m.theme.panel.Width(max(20, width-2)).Height(max(5, height-2)).Align(lipgloss.Center, lipgloss.Center).Render(body)
}

func (m *Model) renderUnlock() string {
	title := "UNLOCK DOMAINOPS"
	detail := "Enter your local vault password. It never leaves this machine."
	if m.unlockFirst {
		title = "CREATE LOCAL VAULT"
		detail = "Protect Cloudflare tokens and private keys with a local password."
	}
	lines := []string{m.theme.brand.Render(title), "", m.theme.mutedText.Render(detail), ""}
	labels := []string{"Password", "Confirm password"}
	for i, input := range m.unlockInputs {
		label := labels[i]
		if i == m.unlockFocus {
			label = m.theme.panelTitle.Render(label)
		} else {
			label = m.theme.mutedText.Render(label)
		}
		lines = append(lines, label, input.View(), "")
	}
	if m.err != nil {
		lines = append(lines, m.theme.statusBad.Render("! "+m.err.Error()), "")
	}
	if m.busy {
		lines = append(lines, m.theme.statusWarn.Render("Unlocking…"))
	} else {
		lines = append(lines, m.theme.mutedText.Render("Tab to move · Enter to continue · Ctrl+C to quit"))
	}
	modal := m.theme.modal.Width(min(62, m.width-8)).Render(strings.Join(lines, "\n"))
	return m.theme.app.Width(m.width).Height(m.height).Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal))
}

func (m *Model) renderCredentialForm() string {
	labels := []string{"Connection label", "Scoped API token", "Account ID (optional)"}
	lines := []string{m.theme.brand.Render("ADD CLOUDFLARE CONNECTION"), "", m.theme.mutedText.Render("User tokens can discover multiple accounts. Add an Account ID only for account-owned tokens."), ""}
	for i, input := range m.credentialInputs {
		label := m.theme.mutedText.Render(labels[i])
		if i == m.credentialFocus {
			label = m.theme.panelTitle.Render(labels[i])
		}
		lines = append(lines, label, input.View(), "")
	}
	if m.err != nil {
		lines = append(lines, m.theme.statusBad.Render("! "+m.err.Error()), "")
	}
	lines = append(lines, m.theme.mutedText.Render("Tab to move · Enter to verify and save · Esc to cancel"))
	modal := m.theme.modal.Width(min(72, m.width-8)).Render(strings.Join(lines, "\n"))
	return m.theme.app.Width(m.width).Height(m.height).Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal))
}

func (m *Model) renderRecordForm() string {
	labels := []string{"Record type", "Name", "Content", "TTL", "Priority"}
	title := "CREATE DNS RECORD"
	if m.recordEditing {
		title = "EDIT DNS RECORD"
	}
	lines := []string{m.theme.brand.Render(title), ""}
	for i, input := range m.recordInputs {
		label := m.theme.mutedText.Render(labels[i])
		if i == m.recordFocus {
			label = m.theme.panelTitle.Render(labels[i])
		}
		lines = append(lines, label, input.View())
	}
	proxy := m.theme.mutedText.Render("DNS only")
	if m.recordProxied {
		proxy = m.theme.statusOK.Render("Cloudflare proxied")
	}
	lines = append(lines, "", "Proxy: "+proxy+"  "+m.theme.key.Render("Ctrl+P")+" toggle")
	if m.err != nil {
		lines = append(lines, "", m.theme.statusBad.Render("! "+m.err.Error()))
	}
	lines = append(lines, "", m.theme.mutedText.Render("Tab to move · Enter on Priority to review/apply · Esc to cancel"))
	modal := m.theme.modal.Width(min(74, m.width-8)).Render(strings.Join(lines, "\n"))
	return m.theme.app.Width(m.width).Height(m.height).Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal))
}

func (m *Model) renderCertificateForm() string {
	var title string
	var labels []string
	switch m.certificateAction {
	case "issue":
		title = "ISSUE WILDCARD CERTIFICATES"
		labels = []string{"Zones (local IDs or unique names)", "Environment", "Contact email", "Nested labels", "Key algorithm"}
	case "import":
		title = "IMPORT CERTIFICATE METADATA"
		labels = []string{"PEM file", "Display name", "Zone"}
	case "export":
		title = "EXPORT CURRENT PEM FILES"
		labels = []string{"Destination"}
	case "revoke":
		title = "REVOKE CERTIFICATE — IRREVERSIBLE"
		labels = []string{"Environment", "Exact lineage name", "Reason code"}
	case "renew":
		title = "RENEW DUE CERTIFICATES"
		labels = []string{"Environment"}
	}
	lines := []string{m.theme.brand.Render(title), ""}
	for i, input := range m.certificateInputs {
		label := m.theme.mutedText.Render(labels[i])
		if i == m.certificateFocus {
			label = m.theme.panelTitle.Render(labels[i])
		}
		lines = append(lines, label, input.View(), "")
	}
	if m.certificateAction == "issue" {
		if zone, ok := m.zoneByID(m.certificateIssueZoneID); ok {
			lines = append(lines, m.theme.mutedText.Render("Selected zone: "+zone.Name+" · local ID "+zone.ID), "")
		}
		terms := m.theme.mutedText.Render("not accepted")
		if m.certificateAcceptTerms {
			terms = m.theme.statusOK.Render("accepted")
		}
		production := m.theme.mutedText.Render("not confirmed")
		if m.certificateConfirmProduction {
			production = m.theme.statusWarn.Render("confirmed")
		}
		lines = append(lines,
			"CA terms: "+terms+"  "+m.theme.key.Render("Ctrl+T")+" toggle",
			"Production: "+production+"  "+m.theme.key.Render("Ctrl+P")+" toggle", "")
	}
	if m.certificateAction == "renew" {
		production := m.theme.mutedText.Render("not confirmed")
		if m.certificateConfirmProduction {
			production = m.theme.statusWarn.Render("confirmed")
		}
		lines = append(lines, "Production: "+production+"  "+m.theme.key.Render("Ctrl+P")+" toggle", "")
	}
	if m.certificateAction == "revoke" {
		lines = append(lines,
			m.theme.mutedText.Render("Expected exact name: ")+m.theme.panelTitle.Render(m.certificateExpectedName),
			m.theme.statusWarn.Render("The CA revocation cannot be undone. Confirm by typing the exact lineage name."), "")
	}
	if m.err != nil {
		lines = append(lines, m.theme.statusBad.Render("! "+m.err.Error()), "")
	}
	lines = append(lines, m.theme.mutedText.Render("Tab to move · Enter on final field to run · Esc to cancel"))
	modal := m.theme.modal.Width(min(76, m.width-8)).Render(strings.Join(lines, "\n"))
	return m.theme.app.Width(m.width).Height(m.height).Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal))
}

func (m *Model) renderDeleteConfirmation() string {
	values := m.filteredRecords()
	var detail string
	if len(values) > 0 {
		record := values[min(m.recordIndex, len(values)-1)]
		detail = fmt.Sprintf("%s  %s  %s", record.Type, record.Name, record.Content)
	}
	return m.confirmation("DELETE DNS RECORD?", detail, "This change is sent immediately after a fresh remote read.")
}

func (m *Model) renderRecordConfirmation() string {
	after := fmt.Sprintf("%s  %s  %s  TTL=%d  proxied=%t", m.recordDraft.Type, m.recordDraft.Name, displayRecordContent(m.recordDraft), m.recordDraft.TTL, m.recordDraft.Proxied)
	detail := "Create\n  " + after
	if m.recordDraftEdit {
		before := "current cached record"
		for _, record := range m.records {
			if record.ID == m.recordDraftID || record.ProviderID == m.recordDraftID {
				before = fmt.Sprintf("%s  %s  %s  TTL=%d  proxied=%t", record.Type, record.Name, displayRecordContent(record), record.TTL, record.Proxied)
				break
			}
		}
		detail = "Before\n  " + before + "\nAfter\n  " + after
	}
	return m.confirmation("APPLY DNS CHANGE?", detail, "DomainOps will re-read the remote record and reject a concurrent change.")
}

func (m *Model) renderTLSConfirmation() string {
	detail := fmt.Sprintf("Mode: %s → %s\nAlways HTTPS: %t → %t\nMinimum TLS: %s → %s\nTLS 1.3: %t → %t", m.tls.Mode, m.tlsDraft.Mode, m.tls.AlwaysUseHTTPS, m.tlsDraft.AlwaysUseHTTPS, m.tls.MinimumTLS, m.tlsDraft.MinimumTLS, m.tls.TLS13, m.tlsDraft.TLS13)
	return m.confirmation("APPLY CLOUDFLARE TLS CHANGES?", detail, "A wrong origin mode can interrupt proxied traffic.")
}

func (m *Model) confirmation(title, detail, warning string) string {
	body := m.theme.brand.Render(title) + "\n\n" + detail + "\n\n" + m.theme.statusWarn.Render(warning) + "\n\n" + m.theme.key.Render("y / Enter") + " apply   " + m.theme.key.Render("n / Esc") + " cancel"
	modal := m.theme.modal.Width(min(66, m.width-8)).Render(body)
	return m.theme.app.Width(m.width).Height(m.height).Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal))
}

func (m *Model) renderHelp() string {
	lines := []string{
		m.theme.brand.Render("KEYBOARD REFERENCE"), "",
		m.theme.key.Render("1…7") + "  Navigate sections", m.theme.key.Render("j / k") + "  Move selection",
		m.theme.key.Render("/") + "  Filter current view", m.theme.key.Render("Ctrl+K") + "  Command palette",
		m.theme.key.Render("r") + "  Synchronize", m.theme.key.Render("a") + "  Add Cloudflare connection",
		m.theme.key.Render("n / e / d") + "  New, edit, delete DNS record", m.theme.key.Render("?") + "  Close this help",
		m.theme.key.Render("n / u / i / x / d") + "  Issue, renew due, import, export, revoke certificate",
		"", m.theme.mutedText.Render("All operations are keyboard-accessible and safe over SSH."),
	}
	if m.recoveryBlocked {
		lines = append(lines, "", m.theme.key.Render("R")+"  Retry blocked crash recovery")
	}
	modal := m.theme.modal.Width(min(72, m.width-8)).Render(strings.Join(lines, "\n"))
	return m.theme.app.Width(m.width).Height(m.height).Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal))
}

func (m *Model) renderPalette() string {
	commands := paletteCommands()
	lines := []string{m.theme.brand.Render("COMMAND PALETTE"), ""}
	for i, command := range commands {
		line := "  " + command
		if i == m.paletteIndex {
			line = m.theme.selected.Width(48).Render("› " + command)
		}
		lines = append(lines, line)
	}
	lines = append(lines, "", m.theme.mutedText.Render("j/k select · Enter run · Esc close"))
	modal := m.theme.modal.Width(min(58, m.width-8)).Render(strings.Join(lines, "\n"))
	return m.theme.app.Width(m.width).Height(m.height).Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal))
}

type cell struct {
	value string
	share int
}

func row(width int, cells []cell) string {
	total := 0
	for _, value := range cells {
		total += value.share
	}
	if total == 0 {
		return ""
	}
	available := max(1, width-len(cells)+1)
	parts := make([]string, 0, len(cells))
	used := 0
	for i, value := range cells {
		cellWidth := available * value.share / total
		if i == len(cells)-1 {
			cellWidth = available - used
		}
		used += cellWidth
		text := truncate(stripLines(value.value), max(0, cellWidth-1))
		parts = append(parts, text+strings.Repeat(" ", max(0, cellWidth-lipgloss.Width(text))))
	}
	return strings.Join(parts, " ")
}

func truncate(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}
	runes := []rune(value)
	for len(runes) > 0 && lipgloss.Width(string(runes))+1 > width {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "…"
}

func stripLines(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func intersperse(values []string, separator string) []string {
	if len(values) <= 1 {
		return values
	}
	result := make([]string, 0, len(values)*2-1)
	for i, value := range values {
		if i > 0 {
			result = append(result, separator)
		}
		result = append(result, value)
	}
	return result
}

func severityRank(value domain.Severity) int {
	switch value {
	case domain.SeverityCritical:
		return 3
	case domain.SeverityWarning:
		return 2
	default:
		return 1
	}
}
