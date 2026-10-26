package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// migrationLockKey is the pg_advisory_lock key serializing migrators across processes and
// replicas ("AegisMig" in ASCII). It lives in the single-bigint advisory key space; the store's
// other advisory locks use the two-int4 key space, which never overlaps with it.
const migrationLockKey int64 = 0x41656769734d6967

// migrationFileName is NNNN_lower_snake_name.sql.
var migrationFileName = regexp.MustCompile(`^([0-9]{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)

// Migration is one versioned schema change embedded in the binary.
type Migration struct {
	Version  int    // 1, 2, 3, … (contiguous)
	Name     string // the part after the version in the file name
	Checksum string // hex SHA-256 of the file contents
	sql      string
}

// appliedMigration is a row of schema_migrations.
type appliedMigration struct {
	Version  int
	Name     string
	Checksum string
}

// MigrateResult reports what Migrate did.
type MigrateResult struct {
	// Applied lists the versions applied by this call (empty when the schema was current).
	Applied []int
	// Version is the schema version after the call.
	Version int
}

// loadMigrations reads, validates and orders the migrations in fsys (a flat directory). Every
// entry must match NNNN_name.sql, versions must be unique, start at 1 and be contiguous, and no
// file may be empty — a stray or misnamed file is an error rather than silently ignored.
func loadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	migrations := make([]Migration, 0, len(entries))
	for _, e := range entries {
		m := migrationFileName.FindStringSubmatch(e.Name())
		if e.IsDir() || m == nil {
			return nil, fmt.Errorf("migration %q: name must match NNNN_lower_snake.sql", e.Name())
		}
		version, _ := strconv.Atoi(m[1]) // four ASCII digits: cannot fail
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", e.Name(), err)
		}
		if len(body) == 0 {
			return nil, fmt.Errorf("migration %q is empty", e.Name())
		}
		sum := sha256.Sum256(body)
		migrations = append(migrations, Migration{
			Version: version, Name: m[2], Checksum: hex.EncodeToString(sum[:]), sql: string(body),
		})
	}
	slices.SortFunc(migrations, func(a, b Migration) int { return a.Version - b.Version })
	for i, m := range migrations {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous from 0001: found %04d at position %d", m.Version, i+1)
		}
	}
	return migrations, nil
}

// planMigrations checks the applied history against the known migrations and returns the ones
// still to apply. It refuses to proceed when an applied migration is unknown, renamed, out of
// order, or its checksum differs from the embedded file (the file was edited after release).
func planMigrations(known []Migration, applied []appliedMigration) ([]Migration, error) {
	for i, a := range applied {
		if i >= len(known) || a.Version > len(known) {
			return nil, fmt.Errorf("%w: version %d (%s); this binary knows up to %d", ErrUnknownMigration, a.Version, a.Name, len(known))
		}
		k := known[i]
		if a.Version != k.Version {
			return nil, fmt.Errorf("%w: applied history has a gap: expected version %d, found %d", ErrUnknownMigration, k.Version, a.Version)
		}
		if a.Name != k.Name {
			return nil, fmt.Errorf("%w: version %d applied as %q but embedded as %q", ErrChecksumMismatch, a.Version, a.Name, k.Name)
		}
		if a.Checksum != k.Checksum {
			return nil, fmt.Errorf("%w: version %d (%s): applied checksum %s, embedded %s", ErrChecksumMismatch, a.Version, a.Name, a.Checksum, k.Checksum)
		}
	}
	return known[len(applied):], nil
}

// Migrate brings the schema up to date with the migrations embedded in this binary. It is safe to
// run concurrently from several processes: a session-level advisory lock serializes migrators,
// each migration runs in its own transaction together with its schema_migrations row, and
// already-applied migrations are verified by checksum before anything new is applied.
func (s *Store) Migrate(ctx context.Context) (MigrateResult, error) {
	sub, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		return MigrateResult{}, fmt.Errorf("store: migrations: %w", err)
	}
	return migrate(ctx, s.pool, sub, s.log)
}

const createMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    integer     PRIMARY KEY CHECK (version > 0),
    name       text        NOT NULL,
    checksum   text        NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT now()
)`

func migrate(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS, log *slog.Logger) (res MigrateResult, err error) {
	known, err := loadMigrations(fsys)
	if err != nil {
		return res, fmt.Errorf("store: %w", err)
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return res, fmt.Errorf("store: migrate: acquire connection: %w", err)
	}
	if err := checkServerVersion(ctx, conn.Conn()); err != nil {
		conn.Release()
		return res, err
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		conn.Release()
		return res, fmt.Errorf("store: migrate: acquire advisory lock: %w", err)
	}
	defer func() {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, uerr := conn.Exec(uctx, "SELECT pg_advisory_unlock($1)", migrationLockKey); uerr != nil {
			// The session may still hold the lock: close it so the server releases the lock,
			// and let Release discard the closed connection.
			_ = conn.Conn().Close(uctx)
		}
		conn.Release()
	}()

	if _, err := conn.Exec(ctx, createMigrationsTable); err != nil {
		return res, fmt.Errorf("store: migrate: create schema_migrations: %w", err)
	}
	rows, err := conn.Query(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return res, fmt.Errorf("store: migrate: read history: %w", err)
	}
	applied, err := pgx.CollectRows(rows, pgx.RowToStructByPos[appliedMigration])
	if err != nil {
		return res, fmt.Errorf("store: migrate: read history: %w", err)
	}
	pending, err := planMigrations(known, applied)
	if err != nil {
		return res, err
	}

	res.Version = len(applied)
	res.Applied = []int{}
	for _, m := range pending {
		start := time.Now()
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			// Schema changes may legitimately run longer than the application statement timeout,
			// but must not queue forever behind application locks.
			if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = 0; SET LOCAL lock_timeout = '30s'"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, m.sql); err != nil { // no arguments: simple protocol, multi-statement
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
				m.Version, m.Name, m.Checksum)
			return err
		})
		if err != nil {
			return res, fmt.Errorf("store: apply migration %04d_%s: %w", m.Version, m.Name, err)
		}
		res.Applied = append(res.Applied, m.Version)
		res.Version = m.Version
		log.InfoContext(ctx, "store: applied migration", slog.Int("version", m.Version),
			slog.String("name", m.Name), slog.Duration("took", time.Since(start)))
	}
	return res, nil
}

func checkServerVersion(ctx context.Context, conn *pgx.Conn) error {
	var v string
	if err := conn.QueryRow(ctx, "SHOW server_version_num").Scan(&v); err != nil {
		return fmt.Errorf("store: read server version: %w", err)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("store: parse server version %q: %w", v, err)
	}
	if n < MinServerVersion {
		return fmt.Errorf("%w: server_version_num %d < %d", ErrUnsupportedServer, n, MinServerVersion)
	}
	return nil
}
