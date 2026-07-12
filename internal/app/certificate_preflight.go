package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/MeghdadFadaee/domainops/internal/certificates"
	"github.com/MeghdadFadaee/domainops/internal/domain"
)

// CertificatePreflight validates local provider routing and cached CAA policy
// before an ACME order is created. The CA remains authoritative and performs
// its own live DNS/CAA checks; this catches deterministic operator errors early.
func (s *Service) CertificatePreflight(ctx context.Context, plan certificates.Plan) error {
	zone, err := s.repo.GetZone(ctx, plan.ZoneID)
	if err != nil {
		return fmt.Errorf("load certificate zone: %w", err)
	}
	if zone.Status != domain.ZoneActive {
		return fmt.Errorf("zone %s is %s; ACME issuance requires an active zone", zone.Name, zone.Status)
	}
	credential, err := s.repo.GetCredential(ctx, zone.PreferredCredentialID)
	if err != nil {
		return fmt.Errorf("load preferred DNS credential: %w", err)
	}
	if credential.Status != domain.CredentialValid {
		return fmt.Errorf("preferred DNS credential %q is %s", credential.Label, credential.Status)
	}

	seenOwners := make(map[string]struct{})
	for _, identifier := range plan.Identifiers {
		base := strings.TrimPrefix(identifier, "*.")
		owner := "_acme-challenge." + base + "."
		if _, duplicate := seenOwners[owner]; duplicate {
			continue
		}
		seenOwners[owner] = struct{}{}
		auth, providerZoneID, resolveErr := s.ResolveDNS01(ctx, owner)
		if resolveErr != nil {
			return resolveErr
		}
		if auth.CredentialID == "" || providerZoneID == "" {
			return fmt.Errorf("DNS-01 owner %s has no explicit zone credential", owner)
		}
	}

	zones, err := s.repo.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("load zones for cached CAA checks: %w", err)
	}
	for _, identifier := range plan.Identifiers {
		base := strings.ToLower(strings.TrimPrefix(identifier, "*."))
		var ancestors []domain.Zone
		for index := range zones {
			name := strings.ToLower(strings.TrimSuffix(zones[index].Name, "."))
			if base != name && !strings.HasSuffix(base, "."+name) {
				continue
			}
			ancestors = append(ancestors, zones[index])
		}
		if len(ancestors) == 0 {
			return fmt.Errorf("no configured zone owns CAA lookup for %s", identifier)
		}
		rootZone := ancestors[0]
		var records []domain.DNSRecord
		for _, ancestor := range ancestors {
			if len(ancestor.Name) < len(rootZone.Name) {
				rootZone = ancestor
			}
			values, recordErr := s.repo.ListDNSRecords(ctx, ancestor.ID)
			if recordErr != nil {
				return fmt.Errorf("load cached CAA records for %s: %w", ancestor.Name, recordErr)
			}
			records = append(records, values...)
		}
		if caaErr := validateLetsEncryptCAA(rootZone.Name, []string{identifier}, records); caaErr != nil {
			return caaErr
		}
	}
	return nil
}

type caaDirective struct {
	flags uint8
	tag   string
	value string
}

func validateLetsEncryptCAA(zoneName string, identifiers []string, records []domain.DNSRecord) error {
	byOwner := make(map[string][]caaDirective)
	for _, record := range records {
		if record.Type != domain.RecordCAA {
			continue
		}
		directive, ok := parseCAADirective(record)
		if !ok {
			continue
		}
		owner := strings.ToLower(strings.TrimSuffix(record.Name, "."))
		byOwner[owner] = append(byOwner[owner], directive)
	}
	zoneName = strings.ToLower(strings.TrimSuffix(zoneName, "."))
	for _, identifier := range identifiers {
		wildcard := strings.HasPrefix(identifier, "*.")
		name := strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(identifier, "."), "*."))
		var directives []caaDirective
		for current := name; ; current = parentDNSName(current) {
			if values := byOwner[current]; len(values) > 0 {
				directives = values
				break
			}
			if current == zoneName || !strings.HasSuffix(current, "."+zoneName) {
				break
			}
		}
		if len(directives) == 0 {
			continue
		}
		for _, directive := range directives {
			if directive.flags&128 != 0 && !knownCAAPropertyTag(directive.tag) {
				return fmt.Errorf("CAA policy for %s contains unknown issuer-critical tag %q", identifier, directive.tag)
			}
		}
		tag := "issue"
		if wildcard {
			for _, directive := range directives {
				if directive.tag == "issuewild" {
					tag = "issuewild"
					break
				}
			}
		}
		relevant, allowed := 0, false
		var methodRestricted, accountRestricted bool
		for _, directive := range directives {
			if directive.tag != tag {
				continue
			}
			relevant++
			issuer, parameters, valid := parseCAAIssueValue(directive.value)
			if !valid || !strings.EqualFold(issuer, "letsencrypt.org") {
				continue
			}
			if methods, constrained := parameters["validationmethods"]; constrained && !containsCAAParameterValue(methods, "dns-01") {
				methodRestricted = true
				continue
			}
			// The engine preflight hook receives only a certificate plan, not the
			// selected ACME account. It therefore cannot safely prove that an
			// account-bound authorization applies. A separate unrestricted
			// letsencrypt.org property may still authorize this DNS-01 order.
			if _, constrained := parameters["accounturi"]; constrained {
				accountRestricted = true
				continue
			}
			allowed = true
		}
		if relevant > 0 && !allowed {
			if accountRestricted {
				return fmt.Errorf("CAA policy for %s authorizes letsencrypt.org only through accounturi, which cannot be verified before the ACME account is selected", identifier)
			}
			if methodRestricted {
				return fmt.Errorf("CAA policy for %s does not authorize letsencrypt.org with validationmethods=dns-01 via %s", identifier, tag)
			}
			return fmt.Errorf("CAA policy for %s does not authorize letsencrypt.org via %s", identifier, tag)
		}
	}
	return nil
}

func knownCAAPropertyTag(tag string) bool {
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "issue", "issuewild", "iodef":
		return true
	default:
		return false
	}
}

// parseCAAIssueValue returns an issuer domain and the RFC 8657 parameters used
// by DomainOps. Unknown parameters remain present but authoritative handling is
// deliberately left to the CA.
func parseCAAIssueValue(value string) (string, map[string][]string, bool) {
	value = strings.TrimSpace(value)
	if unquoted, err := strconv.Unquote(value); err == nil {
		value = unquoted
	}
	parts := strings.Split(value, ";")
	issuer := strings.TrimSuffix(strings.TrimSpace(parts[0]), ".")
	parameters := make(map[string][]string)
	for _, raw := range parts[1:] {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return issuer, parameters, false
		}
		name, parameterValue, found := strings.Cut(raw, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		parameterValue = strings.TrimSpace(parameterValue)
		if !found || name == "" || parameterValue == "" {
			return issuer, parameters, false
		}
		parameters[name] = append(parameters[name], parameterValue)
	}
	return issuer, parameters, true
}

func containsCAAParameterValue(values []string, wanted string) bool {
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(candidate), wanted) {
				return true
			}
		}
	}
	return false
}

func parseCAADirective(record domain.DNSRecord) (caaDirective, bool) {
	var structured struct {
		Flags uint8  `json:"flags"`
		Tag   string `json:"tag"`
		Value string `json:"value"`
	}
	if len(record.Data) > 0 && string(record.Data) != "null" && json.Unmarshal(record.Data, &structured) == nil && structured.Tag != "" {
		return caaDirective{flags: structured.Flags, tag: strings.ToLower(structured.Tag), value: structured.Value}, true
	}
	parts := strings.Fields(record.Content)
	if len(parts) < 3 {
		return caaDirective{}, false
	}
	flags, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return caaDirective{}, false
	}
	value := strings.Join(parts[2:], " ")
	if unquoted, err := strconv.Unquote(value); err == nil {
		value = unquoted
	}
	return caaDirective{flags: uint8(flags), tag: strings.ToLower(parts[1]), value: value}, true
}

func parentDNSName(name string) string {
	if index := strings.IndexByte(name, '.'); index >= 0 {
		return name[index+1:]
	}
	return ""
}
