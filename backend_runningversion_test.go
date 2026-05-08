// White-box tests for the version-stamping behavior in
// newBackend. Lives outside backend_test.go because that file is
// //go:build acceptance (full vault subprocess) and runs in
// package argon2id_test; this file is in package argon2id so it
// can read the package-level PluginVersion var directly.

package argon2id

import "testing"

// TestNewBackend_advertisesPluginVersion confirms that the
// running-version stamp set in PluginVersion is propagated to
// framework.Backend.RunningVersion. Vault surfaces this in
// `vault plugin info` for operators; without the wiring the
// plugin would advertise no version even when goreleaser stamps
// one at link time.
func TestNewBackend_advertisesPluginVersion(t *testing.T) {
	const stamped = "v9.9.9-test"

	prior := PluginVersion
	PluginVersion = stamped
	t.Cleanup(func() { PluginVersion = prior })

	b, err := newBackend()
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	if got := b.RunningVersion; got != stamped {
		t.Errorf("RunningVersion: got %q, want %q", got, stamped)
	}
}

// TestNewBackend_emptyVersionWhenUnstamped confirms that an
// un-stamped local build (PluginVersion == "") leaves
// RunningVersion empty rather than reporting a sentinel string.
// Vault validates RunningVersion as semver and rejects sentinels
// like "dev" — empty is the right "unset" signal.
func TestNewBackend_emptyVersionWhenUnstamped(t *testing.T) {
	prior := PluginVersion
	PluginVersion = ""
	t.Cleanup(func() { PluginVersion = prior })

	b, err := newBackend()
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	if got := b.RunningVersion; got != "" {
		t.Errorf("RunningVersion: got %q, want empty string for unstamped build", got)
	}
}
