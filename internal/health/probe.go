// Package health performs cancellable public DNS and TLS observations without
// coupling network activity to TUI rendering.
package health

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"crypto/tls"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Prober struct {
	Resolver Resolver
	Dialer   Dialer
	RootCAs  *x509.CertPool
	Timeout  time.Duration
	Now      func() time.Time
}

func NewProber() *Prober {
	return &Prober{
		Resolver: net.DefaultResolver,
		Dialer:   &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		Timeout:  15 * time.Second,
		Now:      time.Now,
	}
}

// Probe resolves the endpoint, tries each address, and performs a TLS handshake
// with SNI. Verification is manual so certificate identity, trust, and expiry
// metadata are still available when validation fails.
func (p *Prober) Probe(ctx context.Context, endpoint domain.ObservedEndpoint) (domain.ObservedEndpoint, error) {
	result := endpoint
	result.ResolvedAddresses = nil
	result.FingerprintSHA256 = ""
	result.Issuer = ""
	result.NotAfter = nil
	result.ValidForHost = false
	result.Trusted = false
	result.LastError = ""

	now := time.Now
	if p != nil && p.Now != nil {
		now = p.Now
	}
	checkedAt := now().UTC()
	result.LastCheckedAt = &checkedAt
	if strings.TrimSpace(endpoint.Host) == "" {
		err := errors.New("endpoint host is empty")
		result.LastError = err.Error()
		return result, err
	}
	port := endpoint.Port
	if port == 0 {
		port = 443
		result.Port = port
	}
	if port < 1 || port > 65535 {
		err := fmt.Errorf("endpoint port %d is outside 1..65535", port)
		result.LastError = err.Error()
		return result, err
	}

	resolver := Resolver(net.DefaultResolver)
	if p != nil && p.Resolver != nil {
		resolver = p.Resolver
	}
	lookup, err := resolver.LookupIPAddr(ctx, endpoint.Host)
	if err != nil {
		err = fmt.Errorf("resolve %s: %w", endpoint.Host, err)
		result.LastError = err.Error()
		return result, err
	}
	for _, address := range lookup {
		if address.IP != nil {
			result.ResolvedAddresses = append(result.ResolvedAddresses, address.IP.String())
		}
	}
	slices.Sort(result.ResolvedAddresses)
	result.ResolvedAddresses = slices.Compact(result.ResolvedAddresses)
	if len(result.ResolvedAddresses) == 0 {
		err = fmt.Errorf("resolve %s: no IP addresses returned", endpoint.Host)
		result.LastError = err.Error()
		return result, err
	}

	timeout := 15 * time.Second
	if p != nil && p.Timeout > 0 {
		timeout = p.Timeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := Dialer(&net.Dialer{Timeout: timeout})
	if p != nil && p.Dialer != nil {
		dialer = p.Dialer
	}

	var attempts []error
	for _, address := range result.ResolvedAddresses {
		raw, dialErr := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
		if dialErr != nil {
			attempts = append(attempts, fmt.Errorf("%s: %w", address, dialErr))
			continue
		}
		connection := tls.Client(raw, &tls.Config{
			ServerName:         endpoint.Host,
			InsecureSkipVerify: true, // Verification is performed independently below.
			MinVersion:         tls.VersionTLS12,
		})
		handshakeErr := connection.HandshakeContext(probeCtx)
		if handshakeErr != nil {
			_ = raw.Close()
			attempts = append(attempts, fmt.Errorf("%s TLS handshake: %w", address, handshakeErr))
			continue
		}
		state := connection.ConnectionState()
		_ = connection.Close()
		if len(state.PeerCertificates) == 0 {
			attempts = append(attempts, fmt.Errorf("%s TLS handshake returned no peer certificate", address))
			continue
		}
		observeCertificate(&result, endpoint.Host, state.PeerCertificates, p.rootCAs(), checkedAt)
		return result, nil
	}

	err = fmt.Errorf("connect to %s:%d: %w", endpoint.Host, port, errors.Join(attempts...))
	result.LastError = err.Error()
	return result, err
}

func (p *Prober) rootCAs() *x509.CertPool {
	if p == nil {
		return nil
	}
	return p.RootCAs
}

func observeCertificate(result *domain.ObservedEndpoint, host string, peers []*x509.Certificate, roots *x509.CertPool, now time.Time) {
	leaf := peers[0]
	digest := sha256.Sum256(leaf.Raw)
	result.FingerprintSHA256 = hex.EncodeToString(digest[:])
	result.Issuer = leaf.Issuer.String()
	notAfter := leaf.NotAfter.UTC()
	result.NotAfter = &notAfter
	result.ValidForHost = leaf.VerifyHostname(host) == nil

	intermediates := x509.NewCertPool()
	for _, certificate := range peers[1:] {
		intermediates.AddCert(certificate)
	}
	options := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	_, trustErr := leaf.Verify(options)
	result.Trusted = trustErr == nil
}
