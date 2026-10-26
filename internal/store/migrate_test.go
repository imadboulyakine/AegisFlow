package store

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func TestLoadMigrations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fsys     fstest.MapFS
		versions []int
		wantErr  string
	}{
		{
			name:     "ordered regardless of directory order",
			fsys:     fstest.MapFS{"0002_b.sql": file("SELECT 2;"), "0001_a_b.sql": file("SELECT 1;")},
			versions: []int{1, 2},
		},
		{name: "empty directory", fsys: fstest.MapFS{}, versions: []int{}},
		{name: "gap", fsys: fstest.MapFS{"0001_a.sql": file("x"), "0003_c.sql": file("x")}, wantErr: "contiguous"},
		{name: "duplicate version", fsys: fstest.MapFS{"0001_a.sql": file("x"), "0001_b.sql": file("x")}, wantErr: "contiguous"},
		{name: "starts at two", fsys: fstest.MapFS{"0002_a.sql": file("x")}, wantErr: "contiguous"},
		{name: "bad name", fsys: fstest.MapFS{"1_init.sql": file("x")}, wantErr: "NNNN_lower_snake"},
		{name: "upper case", fsys: fstest.MapFS{"0001_Init.sql": file("x")}, wantErr: "NNNN_lower_snake"},
		{name: "stray file", fsys: fstest.MapFS{"0001_a.sql": file("x"), "README.md": file("x")}, wantErr: "NNNN_lower_snake"},
		{name: "directory", fsys: fstest.MapFS{"0001_a.sql/x": file("x")}, wantErr: "NNNN_lower_snake"},
		{name: "empty file", fsys: fstest.MapFS{"0001_a.sql": file("")}, wantErr: "is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := loadMigrations(tt.fsys)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("loadMigrations() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadMigrations() unexpected error: %v", err)
			}
			if len(got) != len(tt.versions) {
				t.Fatalf("got %d migrations, want %d", len(got), len(tt.versions))
			}
			for i, m := range got {
				if m.Version != tt.versions[i] || len(m.Checksum) != 64 || m.sql == "" {
					t.Errorf("migration %d = %+v", i, m)
				}
			}
		})
	}
}

func TestLoadMigrationsChecksumAndName(t *testing.T) {
	t.Parallel()
	a, err := loadMigrations(fstest.MapFS{"0001_init_schema.sql": file("SELECT 1;")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadMigrations(fstest.MapFS{"0001_init_schema.sql": file("SELECT 1; ")})
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Name != "init_schema" {
		t.Errorf("Name = %q, want init_schema", a[0].Name)
	}
	// printf 'SELECT 1;' | sha256sum
	if want := "17db4fd369edb9244b9f91d9aeed145c3d04ad8ba6e95d06247f07a63527d11a"; a[0].Checksum != want {
		t.Errorf("Checksum = %q, want %q", a[0].Checksum, want)
	}
	if a[0].Checksum == b[0].Checksum {
		t.Error("a one-byte change must change the checksum")
	}
}

func TestEmbeddedMigrationsAreValid(t *testing.T) {
	t.Parallel()
	sub, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	ms, err := loadMigrations(sub)
	if err != nil {
		t.Fatalf("embedded migrations: %v", err)
	}
	if len(ms) < 2 {
		t.Fatalf("expected at least 2 embedded migrations, got %d", len(ms))
	}
	for _, m := range ms {
		// Every migration runs inside a transaction; statements that cannot are forbidden.
		upper := strings.ToUpper(m.sql)
		for _, bad := range []string{"CONCURRENTLY", "BEGIN;", "COMMIT;", "VACUUM"} {
			if strings.Contains(upper, bad) {
				t.Errorf("migration %04d_%s contains %q, which cannot run in the migration transaction", m.Version, m.Name, bad)
			}
		}
	}
}

func TestPlanMigrations(t *testing.T) {
	t.Parallel()
	known, err := loadMigrations(fstest.MapFS{
		"0001_a.sql": file("SELECT 1;"), "0002_b.sql": file("SELECT 2;"), "0003_c.sql": file("SELECT 3;"),
	})
	if err != nil {
		t.Fatal(err)
	}
	applied := func(n int) []appliedMigration {
		out := make([]appliedMigration, n)
		for i := range n {
			out[i] = appliedMigration{Version: known[i].Version, Name: known[i].Name, Checksum: known[i].Checksum}
		}
		return out
	}

	tests := []struct {
		name    string
		applied []appliedMigration
		pending []int
		wantErr error
	}{
		{name: "fresh database", applied: nil, pending: []int{1, 2, 3}},
		{name: "partially applied", applied: applied(1), pending: []int{2, 3}},
		{name: "current", applied: applied(3), pending: []int{}},
		{
			name:    "modified after apply",
			applied: []appliedMigration{{Version: 1, Name: "a", Checksum: strings.Repeat("0", 64)}},
			wantErr: ErrChecksumMismatch,
		},
		{
			name:    "renamed after apply",
			applied: []appliedMigration{{Version: 1, Name: "renamed", Checksum: known[0].Checksum}},
			wantErr: ErrChecksumMismatch,
		},
		{
			name:    "database newer than binary",
			applied: append(applied(3), appliedMigration{Version: 4, Name: "d", Checksum: known[0].Checksum}),
			wantErr: ErrUnknownMigration,
		},
		{
			name:    "gap in history",
			applied: []appliedMigration{applied(1)[0], {Version: 3, Name: "c", Checksum: known[2].Checksum}},
			wantErr: ErrUnknownMigration,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pending, err := planMigrations(known, tt.applied)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("planMigrations() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("planMigrations() unexpected error: %v", err)
			}
			got := make([]int, len(pending))
			for i, m := range pending {
				got[i] = m.Version
			}
			if len(got) != len(tt.pending) {
				t.Fatalf("pending = %v, want %v", got, tt.pending)
			}
			for i := range got {
				if got[i] != tt.pending[i] {
					t.Fatalf("pending = %v, want %v", got, tt.pending)
				}
			}
		})
	}
}
