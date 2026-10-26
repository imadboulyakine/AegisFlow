package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestClassifySQLStates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code string
		want error // nil = passed through unchanged
	}{
		{immutableSQLState, ErrImmutable},
		{"23505", ErrConflict},
		{"23P01", ErrConflict},
		{"23001", ErrConflict},
		{"23503", ErrNotFound},
		{"23502", ErrInvalidInput},
		{"23514", ErrInvalidInput},
		{"22001", ErrInvalidInput},
		{"22P02", ErrInvalidInput},
		{"22P05", ErrInvalidInput},
		{"54000", ErrInvalidInput},
		{"40001", nil},
		{"57014", nil}, // query_canceled
	}
	sentinels := []error{ErrImmutable, ErrConflict, ErrNotFound, ErrInvalidInput}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			t.Parallel()
			pgErr := &pgconn.PgError{Code: tt.code, Message: "boom"}
			got := classify(fmt.Errorf("wrapped: %w", pgErr))
			var back *pgconn.PgError
			if !errors.As(got, &back) || back.Code != tt.code {
				t.Fatalf("classify() lost the PgError: %v", got)
			}
			for _, s := range sentinels {
				if want := tt.want != nil && errors.Is(tt.want, s); errors.Is(got, s) != want {
					t.Errorf("errors.Is(classify(%s), %v) = %v, want %v", tt.code, s, !want, want)
				}
			}
		})
	}
}

func TestRetryable(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]bool{"40001": true, "40P01": true, "23505": false, "": false} {
		if got := retryable(fmt.Errorf("x: %w", &pgconn.PgError{Code: code})); got != want {
			t.Errorf("retryable(%q) = %v, want %v", code, got, want)
		}
	}
}

func TestInTxRetries(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	ctx := context.Background()

	attempts := 0
	err := s.inTx(ctx, "test", func(pgx.Tx) error {
		attempts++
		if attempts < 3 {
			return &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("inTx() = %v after %d attempts, want success on the 3rd", err, attempts)
	}

	attempts = 0
	err = s.inTx(ctx, "test", func(pgx.Tx) error {
		attempts++
		return &pgconn.PgError{Code: "40001", Message: "could not serialize access"}
	})
	if sqlState(err) != "40001" || attempts != maxTxAttempts {
		t.Fatalf("inTx() = %v after %d attempts, want the serialization failure after %d", err, attempts, maxTxAttempts)
	}

	attempts = 0
	err = s.inTx(ctx, "test", func(pgx.Tx) error {
		attempts++
		return &pgconn.PgError{Code: "23505"}
	})
	if !errors.Is(err, ErrConflict) || attempts != 1 {
		t.Fatalf("inTx() = %v after %d attempts, want ErrConflict without retry", err, attempts)
	}

	cctx, cancel := context.WithCancel(ctx)
	err = s.inTx(cctx, "test", func(pgx.Tx) error {
		cancel() // cancelled while backing off before the retry
		return &pgconn.PgError{Code: "40P01"}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("inTx() with a cancelled context = %v, want context.Canceled", err)
	}
}

func TestOpenSessionSettings(t *testing.T) {
	t.Parallel()
	if os.Getenv(envTestDatabaseURL) == "" {
		t.Skipf("%s is not set", envTestDatabaseURL)
	}
	ctx := context.Background()
	show := func(s *Store, name string) string {
		t.Helper()
		var v string
		if err := s.pool.QueryRow(ctx, "SELECT current_setting($1)", name).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	s, err := Open(ctx, os.Getenv(envTestDatabaseURL), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := show(s, "statement_timeout"); got != "1min" {
		t.Errorf("default statement_timeout = %q, want 1min", got)
	}
	if got := show(s, "application_name"); got != "aegisflow" {
		t.Errorf("application_name = %q", got)
	}

	u, _ := url.Parse(os.Getenv(envTestDatabaseURL))
	q := u.Query()
	q.Set("statement_timeout", "5000")
	u.RawQuery = q.Encode()
	fromURL, err := Open(ctx, u.String(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer fromURL.Close()
	if got := show(fromURL, "statement_timeout"); got != "5s" {
		t.Errorf("statement_timeout from URL = %q, want 5s", got)
	}
	explicit, err := Open(ctx, u.String(), Options{StatementTimeout: 2 * time.Second, MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer explicit.Close()
	if got := show(explicit, "statement_timeout"); got != "2s" {
		t.Errorf("explicit statement_timeout = %q, want 2s", got)
	}

	u.Host = "127.0.0.1:1" // nothing listens there
	if _, err := Open(ctx, u.String(), Options{}); err == nil {
		t.Error("Open() to a closed port succeeded")
	}
}

func TestEvidenceWithNULIsRejected(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	f := seed(t, s, 1)
	// Valid JSON, but PostgreSQL jsonb cannot store U+0000: surfaced as ErrInvalidInput.
	_, err := s.AppendEvidence(context.Background(), evidenceInput(func(e *EvidenceInput) {
		e.RunID, e.ArtifactID, e.Body = f.runID, f.artifactID, []byte(`{"message":"a\u0000b"}`)
	}))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("AppendEvidence() = %v, want ErrInvalidInput", err)
	}
}
