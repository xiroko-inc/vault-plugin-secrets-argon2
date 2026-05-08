// Fuzz tests for the byte-level PHC parser. ParsePHC sees data
// that an attacker could in principle influence (the threat model
// in docs/threat-model.md treats stored hash entries as
// attacker-tampered if Vault storage is compromised), so we want
// the parser to fail closed on every input shape rather than
// panic.
//
// The contract under fuzz: ParsePHC and Verify must NEVER panic.
// They may return an error, return non-matching values, or accept
// the input — but they must not crash the calling goroutine.

package argon2id

import (
	"strings"
	"testing"
)

// FuzzParsePHC drives ParsePHC with arbitrary bytes interpreted
// as a PHC string. Seed corpus covers the canonical happy-path
// vector plus several pathological shapes — empty input, all
// separators, missing salt/key segments, wrong algorithm, garbage
// numerics — so the fuzzer starts from coverage of every error
// path and explores from there.
func FuzzParsePHC(f *testing.F) {
	seeds := []string{
		// Reference vector from phc-winner-argon2 (already pinned in
		// argon2id_test.go) — guarantees the fuzzer starts from a
		// passing-parse seed and explores mutations.
		referencePHC,
		// Empty + all-separators: exercise the segment-count branch.
		"",
		"$",
		"$$",
		"$$$",
		"$$$$",
		"$$$$$",
		"$$$$$$",
		// Wrong leading separator.
		"argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		// Wrong algorithm.
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		"$bcrypt$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		// Wrong version.
		"$argon2id$v=16$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		"$argon2id$v=$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		"$argon2id$v=foo$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		// Mangled params block.
		"$argon2id$v=19$$c2FsdHNhbHRzYWx0c2FsdA$abc",
		"$argon2id$v=19$m=,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		"$argon2id$v=19$m=65536,t=,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		"$argon2id$v=19$m=65536,t=3,p=$c2FsdHNhbHRzYWx0c2FsdA$abc",
		// Out-of-range numerics that previously slipped past the
		// post-cast bounds check (see PR #1 R3) — fuzzer should
		// never find a way to get past these.
		"$argon2id$v=19$m=99999999999,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		"$argon2id$v=19$m=-1,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
		// Salt / key non-base64.
		"$argon2id$v=19$m=65536,t=3,p=2$!!!$abc",
		"$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$!!!",
		// Empty salt or key.
		"$argon2id$v=19$m=65536,t=3,p=2$$abc",
		"$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$",
		// Multi-byte runes in fields where ASCII is expected — common
		// place for parsers to surprise themselves.
		"$argon2id$v=19$m=65536,t=3,p=2$" + strings.Repeat("é", 8) + "$abc",
		// Long input — fuzzer would build up to this anyway, but
		// seeding it makes sure the bounds-before-decode guard
		// trips early.
		"$argon2id$v=19$m=65536,t=3,p=2$" + strings.Repeat("A", 100000) + "$abc",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, phc string) {
		// The contract is "structured success or structured error,
		// never panic." Discard the return values; the recover would
		// fire on a panic and fail the test, which is what we want.
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ParsePHC panicked on input %q: %v", phc, r)
			}
		}()
		_, _, _, _, _, _ = ParsePHC(phc)
	})
}

// FuzzVerify exercises the full Verify path including the bounds
// validation that runs after ParsePHC returns, so a crash in the
// post-parse code (Equal, IDKey wiring, drift comparison) shows
// up here even when ParsePHC itself is fine.
func FuzzVerify(f *testing.F) {
	for _, phc := range []string{
		referencePHC,
		"",
		"$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$abc",
	} {
		f.Add("password", phc)
	}

	f.Fuzz(func(t *testing.T, password, phc string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Verify panicked on (password=%q phc=%q): %v", password, phc, r)
			}
		}()
		_, _, _ = Verify([]byte(password), phc, defaultParams())
	})
}
