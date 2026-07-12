// Package secrets provides DomainOps' encrypted local secret store.
package secrets

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/MeghdadFadaee/domainops/internal/identifier"
	"github.com/MeghdadFadaee/domainops/internal/store"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	vaultVersion  = 1
	keySize       = chacha20poly1305.KeySize
	saltSize      = 16
	directoryMode = 0o700
	fileMode      = 0o600

	defaultArgonTime    = uint32(3)
	defaultArgonMemory  = uint32(64 * 1024)
	defaultArgonThreads = uint8(4)
)

var (
	// ErrLocked means the vault must be unlocked before accessing secrets.
	ErrLocked = errors.New("secrets: vault is locked")
	// ErrSecretNotFound means no secret exists for the supplied reference.
	ErrSecretNotFound = errors.New("secrets: secret not found")
	// ErrPassphraseRequired means no passphrase or usable keyring key was supplied.
	ErrPassphraseRequired = errors.New("secrets: passphrase required")
	// ErrInvalidPassphrase means the passphrase could not unwrap the vault key.
	ErrInvalidPassphrase = errors.New("secrets: invalid passphrase")
	// ErrCorruptVault means the encrypted vault envelope failed validation or authentication.
	ErrCorruptVault = errors.New("secrets: corrupt vault")
)

const (
	wrappedKeyAAD = "domainops/vault/v1/wrapped-key"
	dataAAD       = "domainops/vault/v1/data"
)

type kdfEnvelope struct {
	Name    string `json:"name"`
	Salt    string `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
}

type cipherEnvelope struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type diskEnvelope struct {
	Version    int            `json:"version"`
	KDF        kdfEnvelope    `json:"kdf"`
	WrappedKey cipherEnvelope `json:"wrapped_key"`
	Data       cipherEnvelope `json:"data"`
}

type vaultPayload struct {
	Entries map[string][]byte `json:"entries"`
}

// Vault encrypts all values using a random XChaCha20-Poly1305 data key. The
// passphrase-derived Argon2id key encrypts only that data key.
type Vault struct {
	mu      sync.RWMutex
	path    string
	service string
	account string

	envelope diskEnvelope
	dataKey  []byte
	entries  map[string][]byte

	// writeEnvelopeOverride is a package-private durability fault-injection
	// seam. Production vaults leave it nil.
	writeEnvelopeOverride func(diskEnvelope) error
}

var _ store.SecretStore = (*Vault)(nil)

// New opens vaultPath. A blank keyringService disables keyring integration,
// which is useful on deliberately headless systems. Existing vaults are
// opportunistically auto-unlocked when a valid data key is available in the
// configured OS keyring; every keyring failure is non-fatal.
func New(vaultPath, keyringService, keyringAccount string) (*Vault, error) {
	if strings.TrimSpace(vaultPath) == "" {
		return nil, errors.New("secrets: vault path is empty")
	}
	absolute, err := filepath.Abs(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("secrets: resolve vault path: %w", err)
	}
	dir := filepath.Dir(absolute)
	if err := os.MkdirAll(dir, directoryMode); err != nil {
		return nil, fmt.Errorf("secrets: create vault directory: %w", err)
	}
	if err := os.Chmod(dir, directoryMode); err != nil {
		return nil, fmt.Errorf("secrets: secure vault directory: %w", err)
	}
	if info, err := os.Lstat(absolute); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("secrets: vault path is not a regular file")
		}
		if err := os.Chmod(absolute, fileMode); err != nil {
			return nil, fmt.Errorf("secrets: secure vault file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("secrets: inspect vault file: %w", err)
	}

	if keyringService != "" && keyringAccount == "" {
		digest := sha256.Sum256([]byte(absolute))
		keyringAccount = fmt.Sprintf("vault-%x", digest[:8])
	}
	vault := &Vault{
		path:    absolute,
		service: keyringService,
		account: keyringAccount,
	}
	if keyringService != "" {
		vault.tryAutoUnlock()
	}
	return vault, nil
}

// NewDefault enables OS-keyring auto-unlock under the DomainOps service name.
func NewDefault(vaultPath string) (*Vault, error) {
	return New(vaultPath, "domainops", "")
}

// Locked reports whether secret values are unavailable.
func (v *Vault) Locked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.dataKey) != keySize
}

// Unlock initializes a missing vault on first use, or decrypts an existing
// vault. An empty passphrase only attempts OS-keyring unlock.
func (v *Vault) Unlock(ctx context.Context, passphrase []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.dataKey) == keySize {
		return nil
	}

	envelope, err := v.readEnvelope()
	if errors.Is(err, os.ErrNotExist) {
		if len(passphrase) == 0 {
			return ErrPassphraseRequired
		}
		return v.initializeLocked(ctx, passphrase)
	}
	if err != nil {
		return err
	}

	var dataKey []byte
	if len(passphrase) == 0 {
		dataKey, err = v.keyFromKeyring()
		if err != nil {
			return ErrPassphraseRequired
		}
	} else {
		dataKey, err = unwrapDataKey(envelope, passphrase)
		if err != nil {
			return err
		}
	}
	defer func() {
		if v.dataKey == nil {
			wipe(dataKey)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := decryptEntries(envelope, dataKey)
	if err != nil {
		return err
	}
	v.envelope = envelope
	v.dataKey = dataKey
	v.entries = entries
	if len(passphrase) != 0 {
		v.saveKeyringKey(dataKey)
	}
	return nil
}

// Lock removes decrypted material from memory.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	wipe(v.dataKey)
	for key, value := range v.entries {
		wipe(value)
		delete(v.entries, key)
	}
	v.dataKey = nil
	v.entries = nil
	v.envelope = diskEnvelope{}
}

// Put stores a copy of value and returns its stable reference. An empty
// reference generates a cryptographically random one.
func (v *Vault) Put(ctx context.Context, reference string, value []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.dataKey) != keySize {
		return "", ErrLocked
	}
	if reference == "" {
		reference = identifier.New("secret")
	}
	next := cloneEntries(v.entries)
	next[reference] = append([]byte(nil), value...)
	if err := v.persistEntriesLocked(next); err != nil {
		var committed *committedEnvelopeError
		if errors.As(err, &committed) {
			wipeEntries(v.entries)
			v.entries = next
			return reference, err
		}
		wipeEntries(next)
		return "", err
	}
	wipeEntries(v.entries)
	v.entries = next
	return reference, nil
}

// Get returns a copy of the secret value.
func (v *Vault) Get(ctx context.Context, reference string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.dataKey) != keySize {
		return nil, ErrLocked
	}
	value, ok := v.entries[reference]
	if !ok {
		return nil, ErrSecretNotFound
	}
	return append([]byte(nil), value...), nil
}

// Delete removes a secret. Deleting an unknown reference is idempotent.
func (v *Vault) Delete(ctx context.Context, reference string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.dataKey) != keySize {
		return ErrLocked
	}
	if _, ok := v.entries[reference]; !ok {
		// Also acts as a durability retry after a prior delete committed its
		// rename but reported a directory-sync error.
		return syncVaultDirectory(filepath.Dir(v.path))
	}
	next := cloneEntries(v.entries)
	wipe(next[reference])
	delete(next, reference)
	if err := v.persistEntriesLocked(next); err != nil {
		var committed *committedEnvelopeError
		if errors.As(err, &committed) {
			wipeEntries(v.entries)
			v.entries = next
			return err
		}
		wipeEntries(next)
		return err
	}
	wipeEntries(v.entries)
	v.entries = next
	return nil
}

func (v *Vault) initializeLocked(ctx context.Context, passphrase []byte) error {
	dataKey := make([]byte, keySize)
	if _, err := rand.Read(dataKey); err != nil {
		return fmt.Errorf("secrets: generate vault key: %w", err)
	}
	defer func() {
		if v.dataKey == nil {
			wipe(dataKey)
		}
	}()
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("secrets: generate KDF salt: %w", err)
	}
	envelope := diskEnvelope{
		Version: vaultVersion,
		KDF: kdfEnvelope{
			Name: "argon2id", Salt: base64.RawStdEncoding.EncodeToString(salt),
			Time: defaultArgonTime, Memory: defaultArgonMemory, Threads: defaultArgonThreads,
		},
	}
	wrappingKey := argon2.IDKey(passphrase, salt, envelope.KDF.Time, envelope.KDF.Memory, envelope.KDF.Threads, keySize)
	wipe(salt)
	defer wipe(wrappingKey)
	wrapped, err := encrypt(wrappingKey, dataKey, []byte(wrappedKeyAAD))
	if err != nil {
		return fmt.Errorf("secrets: wrap vault key: %w", err)
	}
	envelope.WrappedKey = wrapped
	entries := make(map[string][]byte)
	payload, err := encryptPayload(dataKey, entries)
	if err != nil {
		return err
	}
	envelope.Data = payload
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := v.writeEnvelope(envelope); err != nil {
		return err
	}
	v.envelope = envelope
	v.dataKey = dataKey
	v.entries = entries
	v.saveKeyringKey(dataKey)
	return nil
}

func unwrapDataKey(envelope diskEnvelope, passphrase []byte) ([]byte, error) {
	salt, err := validateEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	defer wipe(salt)
	wrappingKey := argon2.IDKey(passphrase, salt, envelope.KDF.Time, envelope.KDF.Memory, envelope.KDF.Threads, keySize)
	defer wipe(wrappingKey)
	dataKey, err := decrypt(wrappingKey, envelope.WrappedKey, []byte(wrappedKeyAAD))
	if err != nil || len(dataKey) != keySize {
		wipe(dataKey)
		return nil, ErrInvalidPassphrase
	}
	return dataKey, nil
}

func validateEnvelope(envelope diskEnvelope) ([]byte, error) {
	if envelope.Version != vaultVersion || envelope.KDF.Name != "argon2id" {
		return nil, ErrCorruptVault
	}
	if envelope.KDF.Time < 1 || envelope.KDF.Time > 10 ||
		envelope.KDF.Memory < 8*1024 || envelope.KDF.Memory > 1024*1024 ||
		envelope.KDF.Threads < 1 || envelope.KDF.Threads > 64 {
		return nil, ErrCorruptVault
	}
	salt, err := base64.RawStdEncoding.DecodeString(envelope.KDF.Salt)
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		wipe(salt)
		return nil, ErrCorruptVault
	}
	return salt, nil
}

func encryptPayload(dataKey []byte, entries map[string][]byte) (cipherEnvelope, error) {
	plain, err := json.Marshal(vaultPayload{Entries: entries})
	if err != nil {
		return cipherEnvelope{}, fmt.Errorf("secrets: encode vault payload: %w", err)
	}
	defer wipe(plain)
	result, err := encrypt(dataKey, plain, []byte(dataAAD))
	if err != nil {
		return cipherEnvelope{}, fmt.Errorf("secrets: encrypt vault payload: %w", err)
	}
	return result, nil
}

func decryptEntries(envelope diskEnvelope, dataKey []byte) (map[string][]byte, error) {
	salt, err := validateEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	wipe(salt)
	plain, err := decrypt(dataKey, envelope.Data, []byte(dataAAD))
	if err != nil {
		return nil, ErrCorruptVault
	}
	defer wipe(plain)
	var payload vaultPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, ErrCorruptVault
	}
	if payload.Entries == nil {
		payload.Entries = make(map[string][]byte)
	}
	return payload.Entries, nil
}

func encrypt(key, plaintext, additionalData []byte) (cipherEnvelope, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return cipherEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return cipherEnvelope{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return cipherEnvelope{
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decrypt(key []byte, encrypted cipherEnvelope, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(encrypted.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, ErrCorruptVault
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil || len(ciphertext) < aead.Overhead() {
		return nil, ErrCorruptVault
	}
	return aead.Open(nil, nonce, ciphertext, additionalData)
}

func (v *Vault) persistEntriesLocked(entries map[string][]byte) error {
	encrypted, err := encryptPayload(v.dataKey, entries)
	if err != nil {
		return err
	}
	next := v.envelope
	next.Data = encrypted
	writeEnvelope := v.writeEnvelope
	if v.writeEnvelopeOverride != nil {
		writeEnvelope = v.writeEnvelopeOverride
	}
	if err := writeEnvelope(next); err != nil {
		var committed *committedEnvelopeError
		if errors.As(err, &committed) {
			v.envelope = next
		}
		return err
	}
	v.envelope = next
	return nil
}

// CommittedWriteError means the atomic rename changed the live vault path, but
// a following permission or directory-durability check failed. Put returns the
// committed reference alongside this error so callers can persist metadata or
// explicitly compensate it instead of leaking an untracked secret.
type CommittedWriteError struct{ err error }

func (e *CommittedWriteError) Error() string { return e.err.Error() }
func (e *CommittedWriteError) Unwrap() error { return e.err }

func IsCommittedWriteError(err error) bool {
	var committed *CommittedWriteError
	return errors.As(err, &committed)
}

type committedEnvelopeError = CommittedWriteError

func (v *Vault) readEnvelope() (diskEnvelope, error) {
	var envelope diskEnvelope
	info, err := os.Lstat(v.path)
	if err != nil {
		return envelope, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return envelope, ErrCorruptVault
	}
	body, err := os.ReadFile(v.path)
	if err != nil {
		return envelope, fmt.Errorf("secrets: read vault: %w", err)
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return envelope, ErrCorruptVault
	}
	salt, err := validateEnvelope(envelope)
	if err != nil {
		return envelope, err
	}
	wipe(salt)
	return envelope, nil
}

func (v *Vault) writeEnvelope(envelope diskEnvelope) error {
	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("secrets: encode vault envelope: %w", err)
	}
	body = append(body, '\n')
	dir := filepath.Dir(v.path)
	temporary, err := os.CreateTemp(dir, ".vault-*")
	if err != nil {
		return fmt.Errorf("secrets: create temporary vault: %w", err)
	}
	temporaryPath := temporary.Name()
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(fileMode); err != nil {
		return fmt.Errorf("secrets: secure temporary vault: %w", err)
	}
	if _, err := temporary.Write(body); err != nil {
		return fmt.Errorf("secrets: write temporary vault: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("secrets: sync temporary vault: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("secrets: close temporary vault: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("secrets: open vault directory before replace: %w", err)
	}
	defer directory.Close()
	if err := os.Rename(temporaryPath, v.path); err != nil {
		return fmt.Errorf("secrets: replace vault: %w", err)
	}
	remove = false
	if err := directory.Sync(); err != nil {
		return &committedEnvelopeError{err: fmt.Errorf("secrets: sync vault directory: %w", err)}
	}
	return nil
}

func syncVaultDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("secrets: open vault directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("secrets: sync vault directory: %w", err)
	}
	return nil
}

func (v *Vault) tryAutoUnlock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	envelope, err := v.readEnvelope()
	if err != nil {
		return
	}
	dataKey, err := v.keyFromKeyring()
	if err != nil {
		return
	}
	entries, err := decryptEntries(envelope, dataKey)
	if err != nil {
		wipe(dataKey)
		return
	}
	v.envelope = envelope
	v.dataKey = dataKey
	v.entries = entries
}

func (v *Vault) keyFromKeyring() ([]byte, error) {
	if v.service == "" {
		return nil, keyring.ErrNotFound
	}
	encoded, err := keyring.Get(v.service, v.account)
	if err != nil {
		return nil, err
	}
	dataKey, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(dataKey) != keySize {
		wipe(dataKey)
		return nil, errors.New("invalid keyring vault key")
	}
	return dataKey, nil
}

func (v *Vault) saveKeyringKey(dataKey []byte) {
	if v.service == "" {
		return
	}
	// Keyring support is an optimization only; headless Linux and unavailable
	// keyrings always continue to use the passphrase path.
	_ = keyring.Set(v.service, v.account, base64.RawStdEncoding.EncodeToString(dataKey))
}

func cloneEntries(source map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(source))
	for key, value := range source {
		result[key] = append([]byte(nil), value...)
	}
	return result
}

func wipeEntries(entries map[string][]byte) {
	for key, value := range entries {
		wipe(value)
		delete(entries, key)
	}
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
