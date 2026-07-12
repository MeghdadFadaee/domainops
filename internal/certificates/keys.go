package certificates

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

// GeneratePrivateKey creates only the two key types intentionally supported by
// DomainOps v1. Randomness always comes from crypto/rand.
func GeneratePrivateKey(algorithm domain.KeyAlgorithm) (crypto.Signer, error) {
	switch algorithm {
	case domain.KeyECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case domain.KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", algorithm)
	}
}

// MarshalPrivateKeyPKCS8 returns a portable unencrypted PKCS#8 PEM. The bytes
// must be sent directly to the encrypted secret store or a mode-0600 export.
func MarshalPrivateKeyPKCS8(key crypto.Signer) ([]byte, error) {
	if key == nil {
		return nil, errors.New("private key is nil")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("private key must contain exactly one PEM block")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key type %T cannot sign", key)
	}
	switch typed := signer.(type) {
	case *ecdsa.PrivateKey:
		if typed.Curve != elliptic.P256() {
			return nil, errors.New("only ECDSA P-256 keys are supported")
		}
	case *rsa.PrivateKey:
		if typed.N.BitLen() != 2048 {
			return nil, errors.New("only RSA-2048 keys are supported")
		}
	default:
		return nil, fmt.Errorf("unsupported private key type %T", signer)
	}
	return signer, nil
}

func keyAlgorithm(key crypto.Signer) (domain.KeyAlgorithm, error) {
	switch typed := key.(type) {
	case *ecdsa.PrivateKey:
		if typed.Curve == elliptic.P256() {
			return domain.KeyECDSAP256, nil
		}
	case *rsa.PrivateKey:
		if typed.N.BitLen() == 2048 {
			return domain.KeyRSA2048, nil
		}
	}
	return "", fmt.Errorf("unsupported private key type %T", key)
}
