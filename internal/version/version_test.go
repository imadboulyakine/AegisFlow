package version

import (
	"runtime"
	"runtime/debug"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	vcs := &debug.BuildInfo{
		GoVersion: "go1.27.3",
		Main:      debug.Module{Path: "github.com/imadboulyakine/aegisflow", Version: "v0.2.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.time", Value: "2026-10-26T12:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}

	tests := []struct {
		name string
		in   Info
		bi   *debug.BuildInfo
		want Info
	}{
		{
			name: "no build info falls back to placeholders",
			in:   Info{},
			bi:   nil,
			want: Info{Version: "dev", Commit: unknown, BuildDate: unknown, GoVersion: runtime.Version()},
		},
		{
			name: "devel main module is not a version",
			in:   Info{},
			bi:   &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "(devel)"}},
			want: Info{Version: "dev", Commit: unknown, BuildDate: unknown, GoVersion: "go1.27.3"},
		},
		{
			name: "vcs info fills empty values",
			in:   Info{},
			bi:   vcs,
			want: Info{
				Version:   "v0.2.0",
				Commit:    "0123456789abcdef0123456789abcdef01234567",
				BuildDate: "2026-10-26T12:00:00Z",
				GoVersion: "go1.27.3",
				Modified:  true,
			},
		},
		{
			name: "ldflags values win over vcs info",
			in:   Info{Version: "v1.0.0", Commit: "abc1234", BuildDate: "2026-01-01T00:00:00Z"},
			bi:   vcs,
			want: Info{
				Version:   "v1.0.0",
				Commit:    "abc1234",
				BuildDate: "2026-01-01T00:00:00Z",
				GoVersion: "go1.27.3",
				Modified:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resolve(tt.in, tt.bi); got != tt.want {
				t.Errorf("resolve() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGetIsStable(t *testing.T) {
	t.Parallel()

	a, b := Get(), Get()
	if a != b {
		t.Fatalf("Get() not stable: %+v vs %+v", a, b)
	}
	if a.Version == "" || a.Commit == "" || a.BuildDate == "" || a.GoVersion == "" {
		t.Fatalf("Get() returned empty fields: %+v", a)
	}
}
