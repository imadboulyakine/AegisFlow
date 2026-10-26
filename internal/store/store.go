// Package store is AegisFlow's PostgreSQL persistence layer (ADR-007, ARCHITECTURE.md §4).
//
// It owns the database schema (embedded, checksummed SQL migrations applied by Migrate) and a
// typed, context-first repository API over a pgx v5 connection pool:
//
//   - projects, pipeline runs and artifacts (UpsertProject, RecordRun, UpsertArtifact);
//   - append-only raw evidence (AppendEvidence) and audit log (AppendAudit), protected by database
//     triggers that reject UPDATE, DELETE and TRUNCATE;
//   - the derived vulnerability model (IngestDocument): components, vulnerabilities, findings and
//     VEX statements, merged idempotently in a single transaction per evidence document;
//   - risk results and finding queries (UpdateFindingRisk, ListFindings) and threat-intel
//     snapshots (RecordVulnIntel, LatestVulnIntel).
//
// Every statement is static SQL with bind parameters; no SQL text is ever built from input values.
// Errors are wrapped with the sentinel values below so callers can map them with errors.Is.
package store

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors. Returned errors wrap one of these (and, when it came from PostgreSQL, the
// underlying *pgconn.PgError), so use errors.Is to classify them.
var (
	// ErrNotFound means a referenced row (project, run, artifact, finding) does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict means the request contradicts an existing row (for example a run attempt
	// re-recorded with a different commit SHA, or an artifact digest with a different kind).
	ErrConflict = errors.New("store: conflict")
	// ErrInvalidInput means a value failed validation in Go or a database CHECK constraint.
	ErrInvalidInput = errors.New("store: invalid input")
	// ErrImmutable means an UPDATE, DELETE or TRUNCATE hit an append-only table.
	ErrImmutable = errors.New("store: record is append-only")
	// ErrChecksumMismatch means an applied migration's embedded SQL changed since it was applied.
	ErrChecksumMismatch = errors.New("store: applied migration was modified")
	// ErrUnknownMigration means the database has a migration this binary does not know about
	// (the schema is newer than the code, or migrations were renumbered).
	ErrUnknownMigration = errors.New("store: unknown migration applied to database")
	// ErrUnsupportedServer means the PostgreSQL server is older than MinServerVersion.
	ErrUnsupportedServer = errors.New("store: unsupported PostgreSQL server version")
)

// immutableSQLState is the SQLSTATE raised by the aegisflow_forbid_mutation() trigger.
const immutableSQLState = "AF001"

// MinServerVersion is the minimum supported PostgreSQL server_version_num (18.0). The store uses
// PostgreSQL 18 features (RETURNING OLD/NEW in upserts).
const MinServerVersion = 180000

// Options tunes Open. The zero value is valid.
type Options struct {
	// Logger receives operational logs (migrations, retries). Nil discards them.
	Logger *slog.Logger
	// MaxConns caps the pool size; 0 keeps pgx's default (max(4, GOMAXPROCS)) unless the URL sets
	// pool_max_conns.
	MaxConns int32
	// StatementTimeout is sent as the session statement_timeout. 0 keeps a statement_timeout
	// given in the URL, else DefaultStatementTimeout.
	StatementTimeout time.Duration
}

// DefaultStatementTimeout bounds every statement of the application's sessions. Migrations
// override it per transaction.
const DefaultStatementTimeout = 60 * time.Second

// Store is the PostgreSQL repository. It is safe for concurrent use.
type Store struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// Open connects to PostgreSQL, verifies connectivity and returns a Store. databaseURL is a
// postgres:// URL or keyword/value DSN; it may contain credentials and is never logged or included
// in errors. Call Migrate before using the repository methods, and Close when done.
func Open(ctx context.Context, databaseURL string, opts Options) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		// The parse error may quote the connection string; pgx redacts passwords only on a
		// best-effort basis, so the detail is withheld entirely.
		return nil, errors.New("store: invalid database URL (details withheld: it may contain credentials)")
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	params := cfg.ConnConfig.RuntimeParams
	if params["application_name"] == "" {
		params["application_name"] = "aegisflow"
	}
	if opts.StatementTimeout > 0 || params["statement_timeout"] == "" {
		timeout := cmp.Or(max(opts.StatementTimeout, 0), DefaultStatementTimeout)
		params["statement_timeout"] = strconv.FormatInt(timeout.Milliseconds(), 10)
	}
	// Abort sessions that leave a transaction open (and its row locks held) for too long.
	if params["idle_in_transaction_session_timeout"] == "" {
		params["idle_in_transaction_session_timeout"] = strconv.FormatInt(DefaultStatementTimeout.Milliseconds(), 10)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: create pool: %w", err)
	}
	s := New(pool, opts.Logger)
	if err := s.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// New wraps an existing pool. The Store does not take ownership of configuration; Close closes
// the pool.
func New(pool *pgxpool.Pool, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Store{pool: pool, log: logger}
}

// Close closes the connection pool, waiting for acquired connections to be released.
func (s *Store) Close() { s.pool.Close() }

// Ping checks that the database is reachable (for readiness probes).
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("store: ping database: %w", err)
	}
	return nil
}

// sqlState returns the PostgreSQL error code carried by err, or "".
func sqlState(err error) string {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code
	}
	return ""
}

// classify wraps PostgreSQL errors with the matching sentinel; other errors are returned as is.
func classify(err error) error {
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) ||
		errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrImmutable) {
		return err // nil or already classified
	}
	switch code := sqlState(err); code {
	case "":
		return err
	case immutableSQLState:
		return fmt.Errorf("%w: %w", ErrImmutable, err)
	case "23505", "23P01", "23001": // unique_violation, exclusion_violation, restrict_violation
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case "23503": // foreign_key_violation on insert: the referenced row does not exist
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case "23502", "23514", // not_null_violation, check_violation
		"22001", "22003", "22007", "22008", // string too long, numeric out of range, bad datetime
		"22021", "22023", "22P02", "22P05", // bad encoding, bad parameter, bad text repr, untranslatable
		"2202E", "22030", "22032", "54000": // array subscript, duplicate JSON key, invalid JSON, too large
		return fmt.Errorf("%w: %w", ErrInvalidInput, err)
	default:
		return err
	}
}

// retryable reports whether a transaction failed only because of concurrency and can be re-run.
func retryable(err error) bool {
	switch sqlState(err) {
	case "40001", "40P01": // serialization_failure, deadlock_detected
		return true
	}
	return false
}

const maxTxAttempts = 4

// inTx runs fn in a READ COMMITTED transaction, retrying (with fresh state, fn must be re-runnable)
// on serialization failures and deadlocks.
func (s *Store) inTx(ctx context.Context, name string, fn func(pgx.Tx) error) error {
	for attempt := 1; ; attempt++ {
		err := pgx.BeginFunc(ctx, s.pool, fn)
		if err == nil {
			return nil
		}
		if attempt >= maxTxAttempts || !retryable(err) {
			return classify(err)
		}
		s.log.WarnContext(ctx, "store: retrying transaction", slog.String("tx", name),
			slog.Int("attempt", attempt), slog.String("sqlstate", sqlState(err)))
		select {
		case <-ctx.Done():
			return fmt.Errorf("store: %s: %w", name, ctx.Err())
		case <-time.After(time.Duration(attempt*attempt) * 10 * time.Millisecond):
		}
	}
}

// invalid builds an ErrInvalidInput error.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, fmt.Sprintf(format, args...))
}
