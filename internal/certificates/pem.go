package certificates

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/identifier"
)

// Metadata is safe to display and persist outside the encrypted vault.
type Metadata struct {
	SerialNumber      string              `json:"serial_number"`
	FingerprintSHA256 string              `json:"fingerprint_sha256"`
	Issuer            string              `json:"issuer"`
	Subject           string              `json:"subject"`
	Identifiers       []string            `json:"identifiers"`
	NotBefore         time.Time           `json:"not_before"`
	NotAfter          time.Time           `json:"not_after"`
	KeyAlgorithm      domain.KeyAlgorithm `json:"key_algorithm"`
}

// Artifact contains the material returned by an ACME server or read for a
// managed certificate. PrivateKeyPEM must be PKCS#8 when exported.
type Artifact struct {
	CertificatePEM []byte   `json:"-"`
	ChainPEM       []byte   `json:"-"`
	PrivateKeyPEM  []byte   `json:"-"`
	Metadata       Metadata `json:"metadata"`
}

// ParseCertificatePEM parses a leaf-first PEM bundle, separates the leaf from
// its chain, and rejects any non-certificate PEM block (especially keys).
func ParseCertificatePEM(data []byte) (*x509.Certificate, []byte, []byte, Metadata, error) {
	var certificates []*x509.Certificate
	var encoded [][]byte
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, nil, nil, Metadata{}, errors.New("certificate input contains invalid PEM data")
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, nil, Metadata{}, fmt.Errorf("certificate input contains forbidden PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, nil, Metadata{}, fmt.Errorf("parse certificate: %w", err)
		}
		certificates = append(certificates, cert)
		encoded = append(encoded, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}))
		rest = remaining
	}
	if len(certificates) == 0 {
		return nil, nil, nil, Metadata{}, errors.New("certificate input contains no certificates")
	}
	leaf := certificates[0]
	if leaf.IsCA {
		return nil, nil, nil, Metadata{}, errors.New("certificate bundle starts with a CA certificate")
	}

	leafPEM := slices.Clone(encoded[0])
	chainPEM := bytes.Join(encoded[1:], nil)
	metadata, err := metadataFromCertificate(leaf)
	if err != nil {
		return nil, nil, nil, Metadata{}, err
	}
	return leaf, leafPEM, chainPEM, metadata, nil
}

// ImportMetadata creates an external, read-only lineage and version. It never
// accepts or stores a private key.
func ImportMetadata(lineageID, name, zoneID string, certificatePEM []byte, now time.Time) (domain.CertificateLineage, domain.CertificateVersion, error) {
	_, _, _, metadata, err := ParseCertificatePEM(certificatePEM)
	if err != nil {
		return domain.CertificateLineage{}, domain.CertificateVersion{}, err
	}
	if lineageID == "" {
		lineageID = identifier.New("lineage")
	}
	if name == "" && len(metadata.Identifiers) > 0 {
		name = metadata.Identifiers[0]
	}
	if name == "" {
		name = metadata.Subject
	}
	versionID := identifier.New("certver")
	lineage := domain.CertificateLineage{
		ID:               lineageID,
		Name:             name,
		ZoneID:           zoneID,
		Source:           domain.CertificateImported,
		Identifiers:      slices.Clone(metadata.Identifiers),
		KeyAlgorithm:     metadata.KeyAlgorithm,
		Profile:          "external",
		CurrentVersionID: versionID,
		CreatedAt:        now.UTC(),
		UpdatedAt:        now.UTC(),
	}
	version := domain.CertificateVersion{
		ID:                versionID,
		LineageID:         lineageID,
		SerialNumber:      metadata.SerialNumber,
		FingerprintSHA256: metadata.FingerprintSHA256,
		Issuer:            metadata.Issuer,
		Identifiers:       slices.Clone(metadata.Identifiers),
		NotBefore:         metadata.NotBefore,
		NotAfter:          metadata.NotAfter,
		CreatedAt:         now.UTC(),
	}
	return lineage, version, nil
}

// ValidateArtifact verifies the leaf/key relationship, requested SANs, and
// basic validity ordering before any material is committed or exported.
func ValidateArtifact(artifact Artifact, expectedIdentifiers []string) (*x509.Certificate, error) {
	leaf, _, _, metadata, err := ParseCertificatePEM(append(slices.Clone(artifact.CertificatePEM), artifact.ChainPEM...))
	if err != nil {
		return nil, err
	}
	if len(artifact.PrivateKeyPEM) == 0 {
		return nil, errors.New("managed certificate has no private key")
	}
	key, err := ParsePrivateKeyPEM(artifact.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	if err := verifyKeyPair(leaf, key); err != nil {
		return nil, err
	}
	if !leaf.NotAfter.After(leaf.NotBefore) {
		return nil, errors.New("certificate validity window is empty")
	}
	expected := slices.Clone(expectedIdentifiers)
	for index := range expected {
		expected[index] = strings.ToLower(strings.TrimSuffix(expected[index], "."))
	}
	slices.Sort(expected)
	expected = slices.Compact(expected)
	if !slices.Equal(metadata.Identifiers, expected) {
		return nil, fmt.Errorf("issued certificate identifiers %v do not exactly match requested identifiers %v", metadata.Identifiers, expected)
	}
	return leaf, nil
}

func metadataFromCertificate(cert *x509.Certificate) (Metadata, error) {
	algorithm, err := publicKeyAlgorithm(cert.PublicKey)
	if err != nil {
		return Metadata{}, err
	}
	identifiers := slices.Clone(cert.DNSNames)
	if len(identifiers) == 0 && cert.Subject.CommonName != "" {
		identifiers = []string{cert.Subject.CommonName}
	}
	for i, name := range identifiers {
		identifiers[i] = strings.ToLower(strings.TrimSuffix(name, "."))
	}
	slices.Sort(identifiers)
	identifiers = slices.Compact(identifiers)
	digest := sha256.Sum256(cert.Raw)
	return Metadata{
		SerialNumber:      strings.ToUpper(cert.SerialNumber.Text(16)),
		FingerprintSHA256: hex.EncodeToString(digest[:]),
		Issuer:            cert.Issuer.String(),
		Subject:           cert.Subject.String(),
		Identifiers:       identifiers,
		NotBefore:         cert.NotBefore.UTC(),
		NotAfter:          cert.NotAfter.UTC(),
		KeyAlgorithm:      algorithm,
	}, nil
}

func publicKeyAlgorithm(publicKey any) (domain.KeyAlgorithm, error) {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return domain.KeyECDSAP256, nil
		case elliptic.P384():
			return domain.KeyAlgorithm("EC384"), nil
		case elliptic.P521():
			return domain.KeyAlgorithm("EC521"), nil
		}
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits >= 2048 {
			return domain.KeyAlgorithm(fmt.Sprintf("RSA%d", bits)), nil
		}
	case ed25519.PublicKey:
		return domain.KeyAlgorithm("ED25519"), nil
	}
	return "", fmt.Errorf("unsupported certificate public key type %T", publicKey)
}

func verifyKeyPair(cert *x509.Certificate, key crypto.Signer) error {
	certPublic, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("marshal private key public component: %w", err)
	}
	if !bytes.Equal(certPublic, keyPublic) {
		return errors.New("certificate and private key do not match")
	}
	return nil
}
