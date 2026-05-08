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
	"fmt"
	"strings"
	"testing"
)

// maxLoggedInputLen caps the bytes the fuzz panic-reporters echo
// back into the test log. The seeded corpus already includes a
// 100KB pathological string, and `go test -fuzz` will explore
// even larger inputs; emitting them in full via %q would blow up
// the log output and slow the fuzzer's per-iteration overhead
// during a panic. Truncating to 256 bytes is enough to recognize
// and reproduce a finding while keeping log volume bounded.
const maxLoggedInputLen = 256

// truncQ returns a Go-quoted form of s suitable for log output,
// truncated at maxLoggedInputLen bytes with a length suffix when
// the original was longer. We avoid %q on the unbounded original
// because formatting alone copies the entire string.
func truncQ(s string) string {
	if len(s) <= maxLoggedInputLen {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("%q...(truncated, full len=%d)", s[:maxLoggedInputLen], len(s))
}

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
		// Truncate the logged input so a 100KB+ pathological seed
		// doesn't drown the failure message.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParsePHC panicked on input %s: %v", truncQ(phc), r)
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
				t.Fatalf("Verify panicked on (password=%s phc=%s): %v",
					truncQ(password), truncQ(phc), r)
			}
		}()
		_, _, _ = Verify([]byte(password), phc, defaultParams())
	})
}
