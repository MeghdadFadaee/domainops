// Package certificates implements certificate planning, ACME issuance, metadata
// inspection, and safe local export.
package certificates

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"golang.org/x/net/idna"
)

const (
	DefaultProfile        = "classic"
	MaxIdentifiers        = 100
	EnvironmentStaging    = "staging"
	EnvironmentProduction = "production"
)

// Plan is one independent ACME certificate order. Bulk operations should use
// one Plan per zone so a failure or rate limit never invalidates other zones.
type Plan struct {
	Name         string              `json:"name"`
	ZoneID       string              `json:"zone_id,omitempty"`
	ZoneName     string              `json:"zone_name"`
	Identifiers  []string            `json:"identifiers"`
	KeyAlgorithm domain.KeyAlgorithm `json:"key_algorithm"`
	Profile      string              `json:"profile"`
}

// NewWildcardPlan returns an apex-plus-wildcard plan. Each nested name adds
// its own exact identifier and one-label wildcard. For example, "api" adds
// api.example.com and *.api.example.com; *.example.com does not cover either
// foo.api.example.com or the apex.
func NewWildcardPlan(zoneID, zoneName string, nestedNames ...string) (Plan, error) {
	zoneName, err := canonicalDNSName(zoneName, false)
	if err != nil {
		return Plan{}, fmt.Errorf("zone name: %w", err)
	}

	identifiers := []string{zoneName, "*." + zoneName}
	for _, nested := range nestedNames {
		nested = strings.TrimSpace(nested)
		if nested == "" {
			continue
		}
		if !strings.Contains(nested, ".") {
			nested += "." + zoneName
		}
		name, canonErr := canonicalDNSName(nested, false)
		if canonErr != nil {
			return Plan{}, fmt.Errorf("nested name %q: %w", nested, canonErr)
		}
		if name == zoneName || !strings.HasSuffix(name, "."+zoneName) {
			return Plan{}, fmt.Errorf("nested name %q is outside zone %q", name, zoneName)
		}
		identifiers = append(identifiers, name, "*."+name)
	}

	plan := Plan{
		Name:         zoneName,
		ZoneID:       zoneID,
		ZoneName:     zoneName,
		Identifiers:  deduplicate(identifiers),
		KeyAlgorithm: domain.KeyECDSAP256,
		Profile:      DefaultProfile,
	}
	return plan, ValidatePlan(plan)
}

// ValidatePlan normalizes no input and returns an error for unsafe or invalid
// order shapes. Callers retain full control of identifier ordering (the first
// identifier becomes the certificate common name when enabled by the CA).
func ValidatePlan(plan Plan) error {
	if len(plan.Identifiers) == 0 {
		return errors.New("certificate plan has no identifiers")
	}
	if len(plan.Identifiers) > MaxIdentifiers {
		return fmt.Errorf("certificate plan has %d identifiers; maximum is %d", len(plan.Identifiers), MaxIdentifiers)
	}
	if plan.KeyAlgorithm != domain.KeyECDSAP256 && plan.KeyAlgorithm != domain.KeyRSA2048 {
		return fmt.Errorf("unsupported key algorithm %q", plan.KeyAlgorithm)
	}
	if strings.TrimSpace(plan.Profile) == "" {
		return errors.New("certificate profile is required")
	}

	zone, err := canonicalDNSName(plan.ZoneName, false)
	if err != nil {
		return fmt.Errorf("zone name: %w", err)
	}
	if zone != plan.ZoneName {
		return fmt.Errorf("zone name %q is not canonical; use %q", plan.ZoneName, zone)
	}

	seen := make(map[string]struct{}, len(plan.Identifiers))
	for _, identifier := range plan.Identifiers {
		canon, canonErr := canonicalDNSName(identifier, true)
		if canonErr != nil {
			return fmt.Errorf("identifier %q: %w", identifier, canonErr)
		}
		if canon != identifier {
			return fmt.Errorf("identifier %q is not canonical; use %q", identifier, canon)
		}
		base := strings.TrimPrefix(canon, "*.")
		if base != zone && !strings.HasSuffix(base, "."+zone) {
			return fmt.Errorf("identifier %q is outside zone %q", identifier, zone)
		}
		if _, ok := seen[canon]; ok {
			return fmt.Errorf("duplicate identifier %q", canon)
		}
		seen[canon] = struct{}{}
	}

	return nil
}

func canonicalDNSName(name string, allowWildcard bool) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return "", errors.New("DNS name is empty")
	}
	if strings.ContainsAny(name, "/:@ \\") {
		return "", errors.New("DNS name must not contain a scheme, port, path, or whitespace")
	}
	wildcard := strings.HasPrefix(name, "*.")
	if strings.Contains(name, "*") && !wildcard {
		return "", errors.New("wildcard must be the complete left-most label")
	}
	if wildcard {
		if !allowWildcard {
			return "", errors.New("wildcards are not allowed here")
		}
		name = strings.TrimPrefix(name, "*.")
		if strings.Contains(name, "*") {
			return "", errors.New("only one wildcard label is allowed")
		}
	}

	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("invalid internationalized DNS name: %w", err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", errors.New("DNS name exceeds 253 bytes")
	}
	if ip := net.ParseIP(ascii); ip != nil {
		return "", errors.New("IP addresses are not supported by DNS-01 plans")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", errors.New("DNS name must contain at least two labels")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", errors.New("DNS label is empty or exceeds 63 bytes")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("DNS labels must not begin or end with a hyphen")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("DNS label %q contains an invalid character", label)
			}
		}
	}

	if wildcard {
		return "*." + ascii, nil
	}
	return ascii, nil
}

func deduplicate(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return slices.Clip(out)
}
