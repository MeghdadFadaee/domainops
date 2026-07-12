package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

type Paths struct {
	DataDir      string
	ConfigDir    string
	CacheDir     string
	Database     string
	Vault        string
	Certificates string
	Exports      string
	Logs         string
}

func Resolve(dataOverride string) (Paths, error) {
	dataDir := dataOverride
	if dataDir == "" {
		dataDir = os.Getenv("DOMAINOPS_DATA_DIR")
	}
	explicitDataDir := dataDir != ""
	var err error
	if dataDir == "" {
		switch runtime.GOOS {
		case "darwin":
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return Paths{}, homeErr
			}
			dataDir = filepath.Join(home, "Library", "Application Support", "DomainOps")
		default:
			base := os.Getenv("XDG_DATA_HOME")
			if base == "" {
				home, homeErr := os.UserHomeDir()
				if homeErr != nil {
					return Paths{}, homeErr
				}
				base = filepath.Join(home, ".local", "share")
			}
			dataDir = filepath.Join(base, "domainops")
		}
	}

	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return Paths{}, err
	}
	if dataDir == string(filepath.Separator) {
		return Paths{}, errors.New("refusing to use filesystem root as the data directory")
	}

	// An explicit data directory must be fully self-contained so headless
	// services and containers do not require HOME or writes outside that root.
	configBase := filepath.Join(dataDir, "config")
	cacheBase := filepath.Join(dataDir, "cache")
	if !explicitDataDir {
		configBase, err = os.UserConfigDir()
		if err != nil {
			configBase = filepath.Join(dataDir, "config")
		}
		cacheBase, err = os.UserCacheDir()
		if err != nil {
			cacheBase = filepath.Join(dataDir, "cache")
		}
	}

	return Paths{
		DataDir:      dataDir,
		ConfigDir:    filepath.Join(configBase, "domainops"),
		CacheDir:     filepath.Join(cacheBase, "domainops"),
		Database:     filepath.Join(dataDir, "domainops.db"),
		Vault:        filepath.Join(dataDir, "vault.json"),
		Certificates: filepath.Join(dataDir, "certificates"),
		Exports:      filepath.Join(dataDir, "exports"),
		Logs:         filepath.Join(dataDir, "logs"),
	}, nil
}

func (p Paths) Ensure() error {
	// ConfigDir and CacheDir are reserved for future use. Create only the
	// directories required by the current runtime, avoiding unrelated writes.
	for _, dir := range []string{p.DataDir, p.Certificates, p.Exports, p.Logs} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}
