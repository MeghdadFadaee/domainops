// Package sqlite implements DomainOps' durable local repository.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/store"
	_ "modernc.org/sqlite"
)

const (
	directoryMode = 0o700
	databaseMode  = 0o600
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Repository is a SQLite-backed store.Repository.
type Repository struct {
	db *sql.DB
}

var _ store.Repository = (*Repository)(nil)

// New creates the database parent directory, opens path, and configures SQLite.
// It intentionally does not run migrations; callers must call Migrate before use.
func New(path string) (*Repository, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite: database path is empty")
	}

	var dsn string
	if path == ":memory:" {
		dsn = "file:domainops-memory?mode=memory&cache=shared"
	} else {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("sqlite: resolve database path: %w", err)
		}
		dir := filepath.Dir(absolute)
		if err := os.MkdirAll(dir, directoryMode); err != nil {
			return nil, fmt.Errorf("sqlite: create database directory: %w", err)
		}
		if err := os.Chmod(dir, directoryMode); err != nil {
			return nil, fmt.Errorf("sqlite: secure database directory: %w", err)
		}
		u := &url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
		dsn = u.String()
	}

	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	// FULL synchronous mode is required for the certificate/challenge journals:
	// an acknowledged intent or final metadata commit must survive power loss
	// before filesystem activation or orphan cleanup can rely on it.
	dsn += separator + "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: connect: %w", err)
	}
	if path != ":memory:" {
		if err := os.Chmod(path, databaseMode); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite: secure database file: %w", err)
		}
	}

	return &Repository{db: db}, nil
}

// Close closes the database and releases its resources.
func (r *Repository) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

// Migrate applies all embedded migrations exactly once, in filename order.
func (r *Repository) Migrate(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL
    )`); err != nil {
		return fmt.Errorf("sqlite: initialize migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("sqlite: read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		var applied int
		err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", entry.Name()).Scan(&applied)
		if err != nil {
			return fmt.Errorf("sqlite: inspect migration %s: %w", entry.Name(), err)
		}
		if applied != 0 {
			continue
		}
		body, err := fs.ReadFile(migrationFiles, "migrations/"+entry.Name())
		if err != nil {
			return fmt.Errorf("sqlite: read migration %s: %w", entry.Name(), err)
		}
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("sqlite: begin migration %s: %w", entry.Name(), err)
		}
		if _, err = tx.ExecContext(ctx, string(body)); err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", entry.Name(), encodeTime(time.Now()))
		}
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlite: apply migration %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("sqlite: commit migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}
