package certificates

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/identifier"
)

type ExportMetadata struct {
	SchemaVersion int                       `json:"schema_version"`
	Lineage       domain.CertificateLineage `json:"lineage"`
	Version       domain.CertificateVersion `json:"version"`
	Certificate   Metadata                  `json:"certificate"`
	ExportedAt    time.Time                 `json:"exported_at"`
}

type ExportResult struct {
	VersionDirectory string `json:"version_directory"`
	CurrentLink      string `json:"current_link"`
	CertificatePath  string `json:"certificate_path"`
	ChainPath        string `json:"chain_path"`
	FullChainPath    string `json:"fullchain_path"`
	PrivateKeyPath   string `json:"private_key_path"`
	MetadataPath     string `json:"metadata_path"`
}

// ExportVersion atomically installs an immutable version directory and then
// atomically moves the "current" symlink. A failed write can therefore never
// expose a half-written certificate as current.
func ExportVersion(root string, lineage domain.CertificateLineage, version domain.CertificateVersion, artifact Artifact, now time.Time) (ExportResult, error) {
	if err := EnsurePrivateDirectoryDurable(root); err != nil {
		return ExportResult{}, fmt.Errorf("prepare explicit export root: %w", err)
	}
	if err := prepareExplicitExportRetry(root, version.ID); err != nil {
		return ExportResult{}, err
	}
	result, exists, err := existingExplicitExport(root, lineage, version, artifact)
	if err != nil {
		return ExportResult{}, err
	}
	if !exists {
		result, err = InstallVersion(root, lineage, version, artifact, now)
		if err != nil {
			return ExportResult{}, err
		}
	}
	if err := ActivateVersion(root, version.ID); err != nil {
		return result, err
	}
	result.CurrentLink = filepath.Join(root, "current")
	return result, nil
}

func prepareExplicitExportRetry(root, versionID string) error {
	if strings.TrimSpace(root) == "" {
		return errors.New("export root is required")
	}
	if err := safePathComponent(versionID); err != nil {
		return fmt.Errorf("version ID: %w", err)
	}
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect export root: %w", err)
	}
	for _, path := range []string{
		filepath.Join(root, ".tmp-"+versionID),
	} {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("clean prior explicit export %s: %w", filepath.Base(path), err)
		}
	}
	if err := syncDirectory(root); err != nil {
		return fmt.Errorf("persist explicit export cleanup: %w", err)
	}
	return nil
}

func existingExplicitExport(root string, lineage domain.CertificateLineage, version domain.CertificateVersion, expected Artifact) (ExportResult, bool, error) {
	versionDirectory := filepath.Join(root, version.ID)
	info, err := os.Lstat(versionDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return ExportResult{}, false, nil
	}
	if err != nil {
		return ExportResult{}, false, fmt.Errorf("inspect existing explicit export: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ExportResult{}, true, errors.New("existing explicit export version is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		return ExportResult{}, true, fmt.Errorf("existing explicit export directory permissions are %04o, want 0700", info.Mode().Perm())
	}
	result := ExportResult{
		VersionDirectory: versionDirectory,
		CertificatePath:  filepath.Join(versionDirectory, "cert.pem"),
		ChainPath:        filepath.Join(versionDirectory, "chain.pem"),
		FullChainPath:    filepath.Join(versionDirectory, "fullchain.pem"),
		PrivateKeyPath:   filepath.Join(versionDirectory, "privkey.pem"),
		MetadataPath:     filepath.Join(versionDirectory, "metadata.json"),
	}
	certificatePEM, err := readPrivateRegularFile(result.CertificatePath)
	if err != nil {
		return ExportResult{}, true, fmt.Errorf("read existing explicit certificate: %w", err)
	}
	chainPEM, err := readPrivateRegularFile(result.ChainPath)
	if err != nil {
		return ExportResult{}, true, fmt.Errorf("read existing explicit chain: %w", err)
	}
	fullChainPEM, err := readPrivateRegularFile(result.FullChainPath)
	if err != nil {
		return ExportResult{}, true, fmt.Errorf("read existing explicit full chain: %w", err)
	}
	keyPEM, err := readPrivateRegularFile(result.PrivateKeyPath)
	if err != nil {
		return ExportResult{}, true, fmt.Errorf("read existing explicit private key: %w", err)
	}
	metadataJSON, err := readPrivateRegularFile(result.MetadataPath)
	if err != nil {
		return ExportResult{}, true, fmt.Errorf("read existing explicit metadata: %w", err)
	}
	identifiers := version.Identifiers
	if len(identifiers) == 0 {
		identifiers = expected.Metadata.Identifiers
	}
	if _, err := ValidateArtifact(expected, identifiers); err != nil {
		return ExportResult{}, true, fmt.Errorf("validate expected explicit export: %w", err)
	}
	_, expectedLeafPEM, expectedChainPEM, expectedMetadata, err := ParseCertificatePEM(append(slices.Clone(expected.CertificatePEM), expected.ChainPEM...))
	if err != nil {
		return ExportResult{}, true, fmt.Errorf("parse expected explicit export: %w", err)
	}
	expectedKey, err := ParsePrivateKeyPEM(expected.PrivateKeyPEM)
	if err != nil {
		return ExportResult{}, true, fmt.Errorf("parse expected explicit private key: %w", err)
	}
	expectedKeyPEM, err := MarshalPrivateKeyPKCS8(expectedKey)
	if err != nil {
		return ExportResult{}, true, fmt.Errorf("encode expected explicit private key: %w", err)
	}
	if err := validateVersionMaterial(version, expectedMetadata); err != nil {
		return ExportResult{}, true, err
	}
	if _, err := ValidateArtifact(Artifact{CertificatePEM: certificatePEM, ChainPEM: chainPEM, PrivateKeyPEM: keyPEM}, identifiers); err != nil {
		return ExportResult{}, true, fmt.Errorf("validate existing explicit export: %w", err)
	}
	if !bytes.Equal(certificatePEM, expectedLeafPEM) || !bytes.Equal(chainPEM, expectedChainPEM) || !bytes.Equal(keyPEM, expectedKeyPEM) {
		return ExportResult{}, true, errors.New("existing explicit export belongs to different certificate material")
	}
	expectedFullChain := append(slices.Clone(expectedLeafPEM), expectedChainPEM...)
	if !bytes.Equal(fullChainPEM, expectedFullChain) {
		return ExportResult{}, true, errors.New("existing explicit full chain does not match certificate and chain")
	}
	if err := validateExistingExportMetadata(metadataJSON, result, lineage, version, expectedMetadata); err != nil {
		return ExportResult{}, true, err
	}
	return result, true, nil
}

func readPrivateRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("path is not a regular, non-symlink file")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("permissions are %04o, want 0600", info.Mode().Perm())
	}
	return os.ReadFile(path)
}

func validateVersionMaterial(version domain.CertificateVersion, metadata Metadata) error {
	if version.FingerprintSHA256 == "" || !strings.EqualFold(version.FingerprintSHA256, metadata.FingerprintSHA256) ||
		version.SerialNumber != metadata.SerialNumber || version.Issuer != metadata.Issuer ||
		!slices.Equal(version.Identifiers, metadata.Identifiers) ||
		!version.NotBefore.Equal(metadata.NotBefore) || !version.NotAfter.Equal(metadata.NotAfter) {
		return errors.New("certificate version metadata does not match expected certificate material")
	}
	return nil
}

func validateExistingExportMetadata(data []byte, result ExportResult, lineage domain.CertificateLineage, version domain.CertificateVersion, certificateMetadata Metadata) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var actual ExportMetadata
	if err := decoder.Decode(&actual); err != nil {
		return fmt.Errorf("parse existing explicit metadata: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("parse existing explicit metadata: trailing JSON data")
	}
	if actual.SchemaVersion != 1 || actual.ExportedAt.IsZero() {
		return errors.New("existing explicit metadata has an unsupported schema or missing export time")
	}
	exportedAt := actual.ExportedAt.UTC()
	expectedVersion := version
	expectedVersion.ExportedAt = &exportedAt
	expectedVersion.ExportPath = result.VersionDirectory
	expectedVersion.CertificatePath = result.CertificatePath
	expectedVersion.ChainPath = result.ChainPath
	expected := ExportMetadata{
		SchemaVersion: 1,
		Lineage:       lineage,
		Version:       expectedVersion,
		Certificate:   certificateMetadata,
		ExportedAt:    exportedAt,
	}
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		return fmt.Errorf("encode existing explicit metadata: %w", err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf("encode expected explicit metadata: %w", err)
	}
	if !bytes.Equal(actualJSON, expectedJSON) {
		return errors.New("existing explicit metadata does not match certificate version and material")
	}
	return nil
}

// InstallVersion durably installs immutable PEM material without advancing
// the current symlink. Managed lifecycle commits use this split phase so the
// database becomes authoritative before filesystem activation.
func InstallVersion(root string, lineage domain.CertificateLineage, version domain.CertificateVersion, artifact Artifact, now time.Time) (ExportResult, error) {
	if root == "" {
		return ExportResult{}, errors.New("export root is required")
	}
	if err := safePathComponent(version.ID); err != nil {
		return ExportResult{}, fmt.Errorf("version ID: %w", err)
	}
	if version.LineageID != "" && lineage.ID != "" && version.LineageID != lineage.ID {
		return ExportResult{}, errors.New("certificate version belongs to another lineage")
	}
	if _, err := ValidateArtifact(artifact, version.Identifiers); err != nil {
		return ExportResult{}, fmt.Errorf("validate certificate material: %w", err)
	}
	_, leafPEM, parsedChain, metadata, err := ParseCertificatePEM(append(slices.Clone(artifact.CertificatePEM), artifact.ChainPEM...))
	if err != nil {
		return ExportResult{}, err
	}
	if err := validateVersionMaterial(version, metadata); err != nil {
		return ExportResult{}, err
	}
	key, err := ParsePrivateKeyPEM(artifact.PrivateKeyPEM)
	if err != nil {
		return ExportResult{}, err
	}
	keyPEM, err := MarshalPrivateKeyPKCS8(key)
	if err != nil {
		return ExportResult{}, err
	}

	if err := EnsurePrivateDirectoryDurable(root); err != nil {
		return ExportResult{}, fmt.Errorf("prepare export root: %w", err)
	}

	// The commit journal records the final version path. Deriving the temporary
	// directory from the same immutable version ID lets startup recovery find
	// and remove plaintext key material even if the process exits before rename.
	tempName := ".tmp-" + version.ID
	tempDir := filepath.Join(root, tempName)
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		return ExportResult{}, fmt.Errorf("create temporary export directory: %w", err)
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.RemoveAll(tempDir)
		}
	}()

	version.ExportedAt = pointer(now.UTC())
	version.ExportPath = filepath.Join(root, version.ID)
	version.CertificatePath = filepath.Join(version.ExportPath, "cert.pem")
	version.ChainPath = filepath.Join(version.ExportPath, "chain.pem")
	exportMetadata := ExportMetadata{
		SchemaVersion: 1,
		Lineage:       lineage,
		Version:       version,
		Certificate:   metadata,
		ExportedAt:    now.UTC(),
	}
	metadataJSON, err := json.MarshalIndent(exportMetadata, "", "  ")
	if err != nil {
		return ExportResult{}, fmt.Errorf("encode export metadata: %w", err)
	}
	metadataJSON = append(metadataJSON, byte(10))
	fullchain := append(slices.Clone(leafPEM), parsedChain...)
	files := map[string][]byte{
		"cert.pem":      leafPEM,
		"chain.pem":     parsedChain,
		"fullchain.pem": fullchain,
		"privkey.pem":   keyPEM,
		"metadata.json": metadataJSON,
	}
	for name, contents := range files {
		if err := writeExclusive(filepath.Join(tempDir, name), contents, 0o600); err != nil {
			return ExportResult{}, err
		}
	}
	if err := syncDirectory(tempDir); err != nil {
		return ExportResult{}, err
	}

	versionDir := filepath.Join(root, version.ID)
	if err := os.Rename(tempDir, versionDir); err != nil {
		return ExportResult{}, fmt.Errorf("install certificate version: %w", err)
	}
	removeTemp = false
	if err := syncDirectory(root); err != nil {
		return ExportResult{}, err
	}

	return ExportResult{
		VersionDirectory: versionDir,
		CertificatePath:  filepath.Join(versionDir, "cert.pem"),
		ChainPath:        filepath.Join(versionDir, "chain.pem"),
		FullChainPath:    filepath.Join(versionDir, "fullchain.pem"),
		PrivateKeyPath:   filepath.Join(versionDir, "privkey.pem"),
		MetadataPath:     filepath.Join(versionDir, "metadata.json"),
	}, nil
}

// EnsurePrivateDirectoryDurable creates every missing directory component with
// owner-only permissions and fsyncs each modified parent. It also syncs an
// existing target and parent, covering directories created earlier in the same
// startup before a certificate commit relies on their persistence.
func EnsurePrivateDirectoryDurable(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("directory path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	root := volume + string(filepath.Separator)
	if filepath.Clean(absolute) == filepath.Clean(root) {
		return errors.New("refusing to use the filesystem root as a private directory")
	}
	relative := strings.TrimPrefix(absolute, root)
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		created := false
		if errors.Is(statErr, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("create directory %s: %w", current, err)
			}
			info, statErr = os.Lstat(current)
			created = statErr == nil
		}
		if statErr != nil {
			return fmt.Errorf("inspect directory %s: %w", current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if current == absolute || !trustedPlatformDirectoryAlias(current) {
				return fmt.Errorf("directory path contains symbolic link %s", current)
			}
			continue
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", current)
		}
		if created {
			if err := os.Chmod(current, 0o700); err != nil {
				return fmt.Errorf("secure directory %s: %w", current, err)
			}
			if err := syncDirectory(filepath.Dir(current)); err != nil {
				return fmt.Errorf("persist directory %s: %w", current, err)
			}
		}
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return fmt.Errorf("secure directory %s: %w", absolute, err)
	}
	if err := syncDirectory(absolute); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(absolute)); err != nil {
		return err
	}
	return nil
}

func trustedPlatformDirectoryAlias(path string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	want := map[string]string{
		string(filepath.Separator) + "etc": "/private/etc",
		string(filepath.Separator) + "tmp": "/private/tmp",
		string(filepath.Separator) + "var": "/private/var",
	}[filepath.Clean(path)]
	if want == "" {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.Clean(resolved) == want
}

// ActivateVersion atomically points root/current at an already installed
// immutable version directory.
func ActivateVersion(root, versionID string) error {
	if root == "" {
		return errors.New("export root is required")
	}
	if err := safePathComponent(versionID); err != nil {
		return fmt.Errorf("version ID: %w", err)
	}
	if err := EnsurePrivateDirectoryDurable(root); err != nil {
		return fmt.Errorf("prepare activation root: %w", err)
	}
	info, err := os.Lstat(filepath.Join(root, versionID))
	if err != nil {
		return fmt.Errorf("stat certificate version: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("certificate version path is not a regular directory")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("certificate version directory permissions are %04o, want 0700", info.Mode().Perm())
	}
	current := filepath.Join(root, "current")
	currentInfo, err := os.Lstat(current)
	if err == nil && currentInfo.Mode()&os.ModeSymlink == 0 {
		return errors.New("refusing to replace non-symlink current path")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect current certificate link: %w", err)
	}
	tempLink := filepath.Join(root, ".current-"+identifier.New("link"))
	if err := os.Symlink(versionID, tempLink); err != nil {
		return fmt.Errorf("create current symlink: %w", err)
	}
	if err := os.Rename(tempLink, current); err != nil {
		_ = os.Remove(tempLink)
		return fmt.Errorf("activate certificate version: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		return err
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", filepath.Base(path), err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	ok = true
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func safePathComponent(value string) error {
	if value == "" || value == "." || value == ".." || filepath.Base(value) != value || strings.Contains(value, "/") || strings.Contains(value, string(filepath.Separator)) {
		return errors.New("must be a non-empty path component")
	}
	return nil
}

func pointer[T any](value T) *T { return &value }
