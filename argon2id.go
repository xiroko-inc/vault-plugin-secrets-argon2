// Package argon2id implements the Argon2id PHC-format primitives that
// back the Vault secrets engine. It is intentionally infrastructure-free
// — no Vault SDK, no logger, no storage. The engine package
// composes these primitives with the framework.Path machinery; this
// file is fully unit-testable against fixed reference vectors.
//
// Format: $argon2id$v=19$m=<m>,t=<t>,p=<p>$<base64-salt>$<base64-hash>
// per the de-facto PHC convention shared by libargon2 / argon2-cffi.
//
// Parameter defaults follow RFC 9106 §4 "second recommended option"
// (t=3, m=64 MiB, p=2, salt=16, key=32). Hard bounds per the
// requirements spec §4.2 are enforced on every Hash and Verify call so
// a tampered storage entry cannot DoS the verify path with absurd
// memory or iteration values.
package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Hard parameter bounds (inclusive) per requirements §4.2. Anything
// outside these bounds is rejected at the API boundary on create AND
// at parse time on verify (defends against tampered storage).
const (
	MinMemoryKiB   uint32 = 8 * 1024    // 8 MiB
	MaxMemoryKiB   uint32 = 1024 * 1024 // 1 GiB
	MinIterations  uint32 = 1
	MaxIterations  uint32 = 100
	MinParallelism uint8  = 1
	MaxParallelism uint8  = 16
	MinSaltLen     uint32 = 16
	MaxSaltLen     uint32 = 64
	MinKeyLen      uint32 = 32
	MaxKeyLen      uint32 = 64
)

// Default parameters (RFC 9106 second-recommended option).
const (
	DefaultMemoryKiB   uint32 = 64 * 1024
	DefaultIterations  uint32 = 3
	DefaultParallelism uint8  = 2
	DefaultSaltLen     uint32 = 16
	DefaultKeyLen      uint32 = 32
)

// Sentinel errors. Callers (including the Vault path handlers) inspect
// these via errors.Is to map onto user-facing 4xx vs 5xx responses.
var (
	// ErrInvalidPHC is returned when a PHC string cannot be parsed,
	// or when its embedded parameters fall outside the policy bounds.
	ErrInvalidPHC = errors.New("argon2id: invalid PHC string")

	// ErrUnsupportedAlgorithm is returned when a PHC string names an
	// algorithm other than argon2id (e.g., argon2i, argon2d, bcrypt).
	// This plugin is argon2id-only by design; alternates are a v1.x
	// roadmap item, not a transparent fallback.
	ErrUnsupportedAlgorithm = errors.New("argon2id: unsupported algorithm")

	// ErrUnsupportedVersion is returned when a PHC string carries an
	// argon2 version other than 0x13 (19) — the only version
	// golang.org/x/crypto/argon2 implements.
	ErrUnsupportedVersion = errors.New("argon2id: unsupported argon2 version")

	// ErrInvalidParams is returned when the caller-supplied Params
	// fall outside the policy bounds.
	ErrInvalidParams = errors.New("argon2id: parameters out of bounds")

	// ErrEmptyPassword is returned when Hash is called with a
	// zero-length password. Defensive guard against caller
	// programmer error — a zero-length password almost certainly
	// means the input field never reached the handler.
	ErrEmptyPassword = errors.New("argon2id: password is empty")
)

// Params is the cost-parameter tuple for one Argon2id invocation.
// MemoryKiB / Iterations / Parallelism are the canonical Argon2id
// cost knobs. SaltLen and KeyLen size the random salt and the
// derived key respectively.
type Params struct {
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	SaltLen     uint32 `json:"salt_len"`
	KeyLen      uint32 `json:"key_len"`
}

// Validate enforces the §4.2 bounds. Returns ErrInvalidParams wrapped
// with a field-specific message on the first violation.
func (p Params) Validate() error {
	if p.MemoryKiB < MinMemoryKiB || p.MemoryKiB > MaxMemoryKiB {
		return fmt.Errorf("%w: memory_kib=%d outside [%d, %d]",
			ErrInvalidParams, p.MemoryKiB, MinMemoryKiB, MaxMemoryKiB)
	}
	if p.Iterations < MinIterations || p.Iterations > MaxIterations {
		return fmt.Errorf("%w: iterations=%d outside [%d, %d]",
			ErrInvalidParams, p.Iterations, MinIterations, MaxIterations)
	}
	if p.Parallelism < MinParallelism || p.Parallelism > MaxParallelism {
		return fmt.Errorf("%w: parallelism=%d outside [%d, %d]",
			ErrInvalidParams, p.Parallelism, MinParallelism, MaxParallelism)
	}
	if p.SaltLen < MinSaltLen || p.SaltLen > MaxSaltLen {
		return fmt.Errorf("%w: salt_len=%d outside [%d, %d]",
			ErrInvalidParams, p.SaltLen, MinSaltLen, MaxSaltLen)
	}
	if p.KeyLen < MinKeyLen || p.KeyLen > MaxKeyLen {
		return fmt.Errorf("%w: key_len=%d outside [%d, %d]",
			ErrInvalidParams, p.KeyLen, MinKeyLen, MaxKeyLen)
	}
	return nil
}

// Equal reports whether two Params refer to the same cost tuple.
// Used by Verify to compute policy_drift.
func (p Params) Equal(other Params) bool {
	return p.MemoryKiB == other.MemoryKiB &&
		p.Iterations == other.Iterations &&
		p.Parallelism == other.Parallelism &&
		p.SaltLen == other.SaltLen &&
		p.KeyLen == other.KeyLen
}

// Hash computes argon2id(password, fresh-salt, params) and returns
// the result as a PHC string ready to store. A new salt is drawn from
// crypto/rand on every call.
func Hash(password []byte, params Params) (string, error) {
	if len(password) == 0 {
		return "", ErrEmptyPassword
	}
	if err := params.Validate(); err != nil {
		return "", err
	}

	salt := make([]byte, params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2id: drawing salt: %w", err)
	}
	key := argon2.IDKey(password, salt,
		params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyLen)

	return formatPHC(params, salt, key), nil
}

// Verify re-derives argon2id(password, parsed-salt, parsed-params)
// from the supplied PHC string and constant-time compares it with the
// embedded key. Returns:
//
//   - (true, drift, nil) on match — drift is true when the stored
//     parameters differ from current.
//   - (false, false, nil) on mismatch — caller treats as wrong password.
//   - (false, false, err) on PHC malformation, unsupported algorithm
//     or version, or out-of-bounds parameters in the stored PHC.
//
// Out-of-bounds stored parameters are an operational issue (corrupt or
// tampered storage), not a wrong-password event. Callers distinguish
// the two via errors.Is(err, ErrInvalidPHC).
func Verify(password []byte, phc string, current Params) (valid bool, drift bool, err error) {
	if len(password) == 0 {
		return false, false, nil
	}
	return verifyRaw(password, phc, current)
}

// verifyRaw is Verify without the empty-password short-circuit.
// Splits algorithm + version checks (which trump bounds) from the
// bounds enforcement so callers see the most-specific error: a PHC
// with an unsupported algorithm reports unsupported-algorithm even if
// the salt is also out of bounds.
func verifyRaw(password []byte, phc string, current Params) (valid bool, drift bool, err error) {
	algo, version, params, salt, key, err := ParsePHC(phc)
	if err != nil {
		return false, false, err
	}
	if algo != "argon2id" {
		return false, false, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algo)
	}
	if version != argon2.Version {
		return false, false, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
	if boundsErr := params.Validate(); boundsErr != nil {
		return false, false, fmt.Errorf("%w: %v", ErrInvalidPHC, boundsErr)
	}

	candidate := argon2.IDKey(password, salt,
		params.Iterations, params.MemoryKiB, params.Parallelism, uint32(len(key)))

	match := subtle.ConstantTimeCompare(candidate, key) == 1
	driftBit := false
	if (current != Params{}) {
		driftBit = !params.Equal(current)
	}
	return match, driftBit, nil
}

// ParsePHC extracts the algorithm name, version, cost parameters,
// salt, and key bytes from a PHC string. Pure structural parsing — it
// does NOT enforce policy bounds. Verify (and consumers that care
// about defense-in-depth against tampered storage) must call
// params.Validate() on the returned Params after checking algorithm
// and version, so the most-specific error surfaces first.
func ParsePHC(s string) (algo string, version int, params Params, salt, key []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" {
		err = fmt.Errorf("%w: expected $algo$v=N$params$salt$hash", ErrInvalidPHC)
		return
	}
	algo = parts[1]

	if _, scanErr := fmt.Sscanf(parts[2], "v=%d", &version); scanErr != nil {
		err = fmt.Errorf("%w: parsing version: %v", ErrInvalidPHC, scanErr)
		return
	}

	var m, t uint32
	var p uint8
	if _, scanErr := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); scanErr != nil {
		err = fmt.Errorf("%w: parsing params: %v", ErrInvalidPHC, scanErr)
		return
	}
	params.MemoryKiB = m
	params.Iterations = t
	params.Parallelism = p

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		err = fmt.Errorf("%w: decoding salt: %v", ErrInvalidPHC, err)
		return
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		err = fmt.Errorf("%w: decoding key: %v", ErrInvalidPHC, err)
		return
	}
	params.SaltLen = uint32(len(salt))
	params.KeyLen = uint32(len(key))

	return algo, version, params, salt, key, nil
}

// formatPHC encodes params, salt, and key as a PHC string.
func formatPHC(p Params, salt, key []byte) string {
	encSalt := base64.RawStdEncoding.EncodeToString(salt)
	encKey := base64.RawStdEncoding.EncodeToString(key)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Parallelism,
		encSalt, encKey)
}
