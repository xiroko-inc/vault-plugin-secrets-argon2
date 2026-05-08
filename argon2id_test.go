// Tests pin the cryptographic core against external static reference
// vectors. The reference vector below comes from the phc-winner-argon2
// project's documented test cases — it is independent of the
// golang.org/x/crypto/argon2 implementation we use, so a regression in
// our wrapper, in PHC encoding, or in the underlying library will all
// surface as a verify failure against the pinned PHC string.
//
// See ../argon2id.go for the production code under test.

package argon2id

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// referencePHC was produced by the phc-winner-argon2 reference impl
// (https://github.com/P-H-C/phc-winner-argon2) with:
//
//	echo -n "password" | argon2 saltsaltsaltsalt -id -t 3 -m 16 -p 2 -l 32 -e
//
// Equivalent to argon2.IDKey([]byte("password"),
//
//	[]byte("saltsaltsaltsalt"), t=3, m=65536 KiB, p=2, keyLen=32).
//
// Parameters chosen to fit the plugin's production bounds (§4.2) so the
// vector verifies through the bounds-enforcing public Verify path.
// Pinning this catches drift in the underlying library, our PHC
// encoder/decoder, or the bounds checks against an authoritative
// external impl.
const (
	referencePassword = "password"
	referenceSalt     = "saltsaltsaltsalt" // 16 bytes — meets MinSaltLen
	referenceTime     = 3
	referenceMemKiB   = 65536
	referenceParallel = 2
	referenceKeyLen   = 32
	referencePHC      = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$W5YkPpWPYkFZL4WMLJ+oLd6p5DAYxQBjnFL2i1bhiFA"
)

// Default production parameters per requirements §4.2.
func defaultParams() Params {
	return Params{
		MemoryKiB:   65536,
		Iterations:  3,
		Parallelism: 2,
		SaltLen:     16,
		KeyLen:      32,
	}
}

// TestReferenceVector_IDKey checks the underlying x/crypto/argon2.IDKey
// against the pinned reference vector. This is the foundational
// independent check — if it fails, every other test below is suspect
// because the library itself is broken.
func TestReferenceVector_IDKey(t *testing.T) {
	got := argon2.IDKey(
		[]byte(referencePassword),
		[]byte(referenceSalt),
		uint32(referenceTime),
		uint32(referenceMemKiB),
		uint8(referenceParallel),
		uint32(referenceKeyLen),
	)

	parts := strings.Split(referencePHC, "$")
	if len(parts) != 6 {
		t.Fatalf("malformed referencePHC: %d segments", len(parts))
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("decoding reference key: %v", err)
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Errorf("argon2.IDKey output differs from phc-winner-argon2 reference vector")
	}
}

// TestParsePHC_referenceVector verifies our parser extracts the same
// fields the phc-winner-argon2 project documents.
func TestParsePHC_referenceVector(t *testing.T) {
	algo, version, params, salt, key, err := ParsePHC(referencePHC)
	if err != nil {
		t.Fatalf("ParsePHC: %v", err)
	}
	if algo != "argon2id" {
		t.Errorf("algorithm: got %q, want argon2id", algo)
	}
	if version != argon2.Version {
		t.Errorf("version: got %d, want %d", version, argon2.Version)
	}
	if params.MemoryKiB != referenceMemKiB {
		t.Errorf("m: got %d, want %d", params.MemoryKiB, referenceMemKiB)
	}
	if params.Iterations != referenceTime {
		t.Errorf("t: got %d, want %d", params.Iterations, referenceTime)
	}
	if params.Parallelism != referenceParallel {
		t.Errorf("p: got %d, want %d", params.Parallelism, referenceParallel)
	}
	if string(salt) != referenceSalt {
		t.Errorf("salt: got %q, want %q", salt, referenceSalt)
	}
	if len(key) != referenceKeyLen {
		t.Errorf("key length: got %d, want %d", len(key), referenceKeyLen)
	}
}

// TestVerify_referenceVector confirms our public Verify returns true
// for the pinned (password, PHC) pair from the external reference
// impl, exercising the full bounds-enforcing parse path.
func TestVerify_referenceVector(t *testing.T) {
	ok, _, err := Verify([]byte(referencePassword), referencePHC, Params{})
	if err != nil {
		t.Fatalf("Verify(reference): err = %v", err)
	}
	if !ok {
		t.Error("Verify(reference): got false, want true — reference vector mismatch")
	}
}

func TestHash_emitsValidPHC(t *testing.T) {
	const password = "correct horse battery staple"
	params := defaultParams()

	phc, err := Hash([]byte(password), params)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if !strings.HasPrefix(phc, "$argon2id$v=19$") {
		t.Errorf("PHC lacks expected prefix: %s", phc)
	}

	algo, version, parsed, salt, key, err := ParsePHC(phc)
	if err != nil {
		t.Fatalf("ParsePHC of own output: %v", err)
	}
	if algo != "argon2id" {
		t.Errorf("algorithm: got %q, want argon2id", algo)
	}
	if version != argon2.Version {
		t.Errorf("version: got %d, want %d", version, argon2.Version)
	}
	if parsed.MemoryKiB != params.MemoryKiB ||
		parsed.Iterations != params.Iterations ||
		parsed.Parallelism != params.Parallelism {
		t.Errorf("params drifted: parsed=%+v, want=%+v", parsed, params)
	}
	if uint32(len(salt)) != params.SaltLen {
		t.Errorf("salt length: got %d, want %d", len(salt), params.SaltLen)
	}
	if uint32(len(key)) != params.KeyLen {
		t.Errorf("key length: got %d, want %d", len(key), params.KeyLen)
	}

	// Independent IDKey-equivalence check.
	expected := argon2.IDKey([]byte(password), salt,
		parsed.Iterations, parsed.MemoryKiB, parsed.Parallelism, params.KeyLen)
	if subtle.ConstantTimeCompare(expected, key) != 1 {
		t.Error("encoded key does not match argon2.IDKey of parsed salt+params")
	}
}

func TestHash_freshSaltPerCall(t *testing.T) {
	const password = "p4ssw0rd"
	a, err := Hash([]byte(password), defaultParams())
	if err != nil {
		t.Fatalf("Hash #1: %v", err)
	}
	b, err := Hash([]byte(password), defaultParams())
	if err != nil {
		t.Fatalf("Hash #2: %v", err)
	}
	if a == b {
		t.Error("two Hash calls with same input produced identical output — salt must be random per call")
	}
}

func TestHash_rejectsEmptyPassword(t *testing.T) {
	if _, err := Hash([]byte{}, defaultParams()); err == nil {
		t.Error("expected error for empty password, got nil")
	}
}

func TestHash_rejectsOutOfBoundsParams(t *testing.T) {
	tests := []struct {
		name   string
		params Params
	}{
		{"memory below floor", Params{MemoryKiB: 1024, Iterations: 3, Parallelism: 2, SaltLen: 16, KeyLen: 32}},
		{"memory above ceiling", Params{MemoryKiB: 2 * 1024 * 1024, Iterations: 3, Parallelism: 2, SaltLen: 16, KeyLen: 32}},
		{"iterations zero", Params{MemoryKiB: 65536, Iterations: 0, Parallelism: 2, SaltLen: 16, KeyLen: 32}},
		{"iterations above ceiling", Params{MemoryKiB: 65536, Iterations: 200, Parallelism: 2, SaltLen: 16, KeyLen: 32}},
		{"parallelism zero", Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 0, SaltLen: 16, KeyLen: 32}},
		{"parallelism above ceiling", Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 32, SaltLen: 16, KeyLen: 32}},
		{"salt below floor", Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 2, SaltLen: 8, KeyLen: 32}},
		{"salt above ceiling", Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 2, SaltLen: 128, KeyLen: 32}},
		{"key below floor", Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 2, SaltLen: 16, KeyLen: 16}},
		{"key above ceiling", Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 2, SaltLen: 16, KeyLen: 128}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Hash([]byte("p"), tt.params)
			if !errors.Is(err, ErrInvalidParams) {
				t.Errorf("err = %v, want wraps ErrInvalidParams", err)
			}
		})
	}
}

func TestVerify_correctAndIncorrect(t *testing.T) {
	const correct = "let me in"
	const wrong = "let me out"

	phc, err := Hash([]byte(correct), defaultParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	ok, drift, err := Verify([]byte(correct), phc, defaultParams())
	if err != nil {
		t.Errorf("Verify(correct): err = %v", err)
	}
	if !ok {
		t.Error("Verify(correct): got false, want true")
	}
	if drift {
		t.Error("Verify(correct): unexpected drift=true with matching params")
	}

	ok, _, err = Verify([]byte(wrong), phc, defaultParams())
	if err != nil {
		t.Errorf("Verify(wrong): err = %v", err)
	}
	if ok {
		t.Error("Verify(wrong): got true, want false")
	}
}

func TestVerify_emptyPasswordFalseNoError(t *testing.T) {
	phc, err := Hash([]byte("nonempty"), defaultParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, _, err := Verify([]byte{}, phc, defaultParams())
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if ok {
		t.Error("got true for empty password, want false")
	}
}

func TestVerify_reportsPolicyDrift(t *testing.T) {
	// Hash with one set of params, verify against a "current" policy
	// with different params — drift must be true.
	stored := Params{MemoryKiB: 32768, Iterations: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32}
	current := Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 2, SaltLen: 16, KeyLen: 32}

	phc, err := Hash([]byte("pw"), stored)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, drift, err := Verify([]byte("pw"), phc, current)
	if err != nil {
		t.Errorf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify: got false, want true")
	}
	if !drift {
		t.Error("Verify: drift=false; expected true when stored params differ from current policy")
	}
}

func TestVerify_rejectsTamperedHash(t *testing.T) {
	phc, err := Hash([]byte("pw"), defaultParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	parts := strings.Split(phc, "$")
	if len(parts) != 6 {
		t.Fatalf("unexpected PHC shape: %d segments", len(parts))
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("decoding key: %v", err)
	}
	key[0] ^= 0x01
	parts[5] = base64.RawStdEncoding.EncodeToString(key)
	tampered := strings.Join(parts, "$")

	ok, _, err := Verify([]byte("pw"), tampered, defaultParams())
	if err != nil {
		t.Errorf("err = %v, want nil for tampered (bytes still parse)", err)
	}
	if ok {
		t.Error("got true for tampered hash — security regression")
	}
}

func TestVerify_rejectsMalformedPHC(t *testing.T) {
	tests := []struct {
		name      string
		phc       string
		wantErrIs error
	}{
		{"wrong segment count", "$argon2id$v=19$m=65536,t=3,p=2$onlyfourparts", ErrInvalidPHC},
		{"non-version segment", "$argon2id$x=19$m=65536,t=3,p=2$c2FsdA$a2V5", ErrInvalidPHC},
		{"non-numeric m", "$argon2id$v=19$m=lots,t=3,p=2$c2FsdA$a2V5", ErrInvalidPHC},
		{"non-base64 salt", "$argon2id$v=19$m=65536,t=3,p=2$!!!notb64$a2V5", ErrInvalidPHC},
		{"argon2i (wrong algo)", "$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$a2V5", ErrUnsupportedAlgorithm},
		{"bcrypt (wrong algo)", "$bcrypt$v=19$m=65536,t=3,p=2$c2FsdA$a2V5", ErrUnsupportedAlgorithm},
		{"version 16 (unsupported)", "$argon2id$v=16$m=65536,t=3,p=2$c2FsdA$a2V5", ErrUnsupportedVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, _, err := Verify([]byte("anything"), tt.phc, defaultParams())
			if ok {
				t.Errorf("got ok=true; want false on malformed input")
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErrIs) {
				t.Errorf("err = %q, expected to wrap %v", err.Error(), tt.wantErrIs)
			}
		})
	}
}

func TestVerify_rejectsOutOfBoundsParams(t *testing.T) {
	// Stored PHC with parameters outside the production bounds must be
	// rejected even if the bytes are otherwise well-formed. Defends
	// against a tampered storage entry that would DoS the verify path.
	tests := []struct {
		name string
		phc  string
	}{
		{"m below floor", "$argon2id$v=19$m=1024,t=3,p=2$" + b64("aaaaaaaaaaaaaaaa") + "$" + b64Bytes(make([]byte, 32))},
		{"m above ceiling", "$argon2id$v=19$m=2097152,t=3,p=2$" + b64("aaaaaaaaaaaaaaaa") + "$" + b64Bytes(make([]byte, 32))},
		{"t above ceiling", "$argon2id$v=19$m=65536,t=200,p=2$" + b64("aaaaaaaaaaaaaaaa") + "$" + b64Bytes(make([]byte, 32))},
		{"p above ceiling", "$argon2id$v=19$m=65536,t=3,p=32$" + b64("aaaaaaaaaaaaaaaa") + "$" + b64Bytes(make([]byte, 32))},
		{"salt too short", "$argon2id$v=19$m=65536,t=3,p=2$" + b64("short") + "$" + b64Bytes(make([]byte, 32))},
		{"key too short", "$argon2id$v=19$m=65536,t=3,p=2$" + b64("aaaaaaaaaaaaaaaa") + "$" + b64Bytes(make([]byte, 16))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Verify([]byte("pw"), tt.phc, defaultParams())
			if !errors.Is(err, ErrInvalidPHC) {
				t.Errorf("err = %v, want wraps ErrInvalidPHC", err)
			}
		})
	}
}

func b64(s string) string         { return base64.RawStdEncoding.EncodeToString([]byte(s)) }
func b64Bytes(b []byte) string    { return base64.RawStdEncoding.EncodeToString(b) }
