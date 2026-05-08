//go:build acceptance

// Acceptance tests run against a real `vault server -dev` subprocess
// with the plugin binary auto-registered via -dev-plugin-dir. This
// covers §9.2 of requirements.md: mount → policy → hash → verify
// (correct, wrong, drift) → delete (404 on subsequent verify) →
// audit-log redaction.
//
// The originally-spec'd in-process `vault.TestCluster` pattern (§9.3)
// does not work cleanly: the `github.com/hashicorp/vault` main module
// uses an internal `replace` directive (`github.com/hashicorp/vault/sdk
// => ./sdk`) so its `vault` package is not importable as a clean
// library against a current SDK. Subprocess-driven testing is the
// pragmatic substitute and matches the "real Vault machinery" intent.
//
// Prerequisites: a `vault` binary on PATH (any 1.20+ release works).
// Each test picks its own free port and configures the API client
// directly — no VAULT_ADDR or VAULT_TOKEN inheritance from the
// developer's environment.
//
// Run with: make acceptance — or `go test -tags acceptance ./...`.
// The build tag keeps `go test ./...` (and `go test -short`) cheap.

package argon2id_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Plugin build cache. The plugin compiles once per `go test`
// invocation (~1s with the cached compile, ~3s cold). Each test
// then copies the cached binary into its own tempdir so vault
// starts cleanly with -dev-plugin-dir. The cache directory is
// reaped in TestMain after m.Run() so repeated runs don't leak
// argon2-plugin-cache-* directories under $TMPDIR.
var (
	pluginCacheOnce sync.Once
	pluginCachePath string
	pluginCacheDir  string
	pluginCacheErr  error
)

// TestMain runs the test binary, then removes the plugin-build
// cache directory so repeated `go test -tags acceptance` runs
// don't leak temp dirs.
func TestMain(m *testing.M) {
	code := m.Run()
	if pluginCacheDir != "" {
		_ = os.RemoveAll(pluginCacheDir)
	}
	os.Exit(code)
}

// safeBuilder wraps strings.Builder with a mutex. The vault
// subprocess writes its log on a background goroutine while the
// test goroutine reads it on failure paths; strings.Builder is not
// concurrency-safe and would trip -race without this wrapper.
type safeBuilder struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *safeBuilder) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuilder) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const (
	devRootToken    = "root"
	pluginName      = "vault-plugin-secrets-argon2"
	mountPath       = "argon2"
	devStartTimeout = 30 * time.Second
)

// devVault holds the subprocess + a configured client. cleanup()
// kills the subprocess and waits for it to exit. Always defer it.
type devVault struct {
	addr      string
	client    *vaultapi.Client
	cmd       *exec.Cmd
	auditPath string
	cleanup   func()
}

// startDevVault builds the plugin, lays it out under
// `<tmp>/plugins/`, computes its SHA-256, launches `vault server -dev`
// with -dev-plugin-dir pointed at the directory, then registers and
// mounts the plugin. Returns when the plugin is reachable via the
// API.
func startDevVault(t *testing.T, withAudit bool) *devVault {
	t.Helper()

	if _, err := exec.LookPath("vault"); err != nil {
		t.Skip("vault binary not on PATH; skipping acceptance test")
	}

	tmp := t.TempDir()
	pluginDir := filepath.Join(tmp, "plugins")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("mkdir plugin dir: %v", err)
	}
	// Resolve symlinks. On macOS, $TMPDIR is `/var/folders/...` but
	// the kernel resolves runtime paths to `/private/var/...` — Vault
	// validates the plugin dir's canonical path against the
	// configured one and refuses to load if they differ.
	resolvedPluginDir, err := filepath.EvalSymlinks(pluginDir)
	if err != nil {
		t.Fatalf("eval symlinks on plugin dir: %v", err)
	}
	pluginDir = resolvedPluginDir

	// Build the plugin once per test-binary invocation (cached via
	// sync.Once across all four acceptance tests), then copy the
	// cached binary into this test's pluginDir.
	cachedBinary, err := cachedPluginBinary()
	if err != nil {
		t.Fatalf("build plugin: %v", err)
	}
	pluginPath := filepath.Join(pluginDir, pluginName)
	if err := copyFile(cachedBinary, pluginPath, 0o755); err != nil {
		t.Fatalf("copy plugin into pluginDir: %v", err)
	}

	// Compute SHA-256 — the plugin catalog needs it to register.
	sum, err := sha256File(pluginPath)
	if err != nil {
		t.Fatalf("sha256 plugin: %v", err)
	}

	// Pick a free port for the dev server (avoid the default 8200 in
	// case it's in use).
	port, err := freePort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	cmd := exec.Command("vault", "server",
		"-dev",
		"-dev-root-token-id="+devRootToken,
		"-dev-listen-address="+addr,
		"-dev-plugin-dir="+pluginDir,
		// Don't write the dev root token to ~/.vault-token. Without
		// this flag, every acceptance run would mutate the
		// developer's home directory and leave a known-token file
		// on disk; CI runners would see less direct impact but the
		// hermeticity claim breaks the moment we add HOME-aware
		// helpers later. Pair with the HOME-redirect in cmd.Env.
		"-dev-no-store-token",
		"-log-level=warn",
	)
	// Hermetic env: filter out every VAULT_* variable from the
	// parent environment, then redirect HOME at the test's tempdir
	// so any ancillary file Vault writes (audit hints, history,
	// etc.) lands in the test sandbox rather than the developer's
	// real home directory. Listing only ADDR/TOKEN/CACERT would
	// still leak VAULT_NAMESPACE, VAULT_SKIP_VERIFY,
	// VAULT_CLIENT_TIMEOUT, etc., any of which can change behavior
	// under test.
	cmd.Env = append(filterVaultEnv(os.Environ()),
		"HOME="+tmp,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("start vault: %v", err)
	}

	// Drain stdout so vault doesn't block on a full pipe. Capture
	// for failure diagnostics; safeBuilder protects against the
	// goroutine/test-thread race -race would otherwise flag.
	var ringBuf safeBuilder
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				_, _ = ringBuf.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	cleanup := func() {
		// Kill is no-op if the process already exited; cmd.Wait
		// reaps the process and releases the os/exec-managed
		// resources (pipes, cmd state). cmd.Wait is the documented
		// counterpart to cmd.Start; cmd.Process.Wait would skip the
		// exec.Cmd cleanup path.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}

	// Wait for the listener to come up.
	cfg := vaultapi.DefaultConfig()
	cfg.Address = "http://" + addr
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		cleanup()
		t.Fatalf("vault client: %v", err)
	}
	client.SetToken(devRootToken)

	// Wait until Vault is initialized AND unsealed AND the API
	// returns a non-error health response. Capture the last health
	// snapshot so the failure message is specific about which of
	// the three conditions never came true.
	deadline := time.Now().Add(devStartTimeout)
	var (
		lastHealth *vaultapi.HealthResponse
		lastErr    error
		ready      bool
	)
	for time.Now().Before(deadline) {
		lastHealth, lastErr = client.Sys().Health()
		if lastErr == nil && lastHealth != nil && lastHealth.Initialized && !lastHealth.Sealed {
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		cleanup()
		t.Fatalf("vault never became ready: lastErr=%v lastHealth=%+v\nstderr:\n%s",
			lastErr, lastHealth, ringBuf.String())
	}

	// Register the plugin in the catalog and mount it. Dev mode
	// auto-discovers binaries in -dev-plugin-dir but does not
	// auto-register them under our chosen plugin name — register
	// explicitly with the SHA we computed.
	//
	// Use a per-operation context with a 30s deadline so a hung
	// dev-server fails fast with a specific error instead of
	// blocking until the overall `go test -timeout` fires.
	opCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Sys().RegisterPluginWithContext(opCtx, &vaultapi.RegisterPluginInput{
		Name:    pluginName,
		Type:    vaultapi.PluginTypeSecrets,
		Command: pluginName,
		SHA256:  sum,
	}); err != nil {
		cleanup()
		t.Fatalf("register plugin: %v", err)
	}

	if err := client.Sys().MountWithContext(opCtx, mountPath, &vaultapi.MountInput{
		Type: pluginName,
	}); err != nil {
		cleanup()
		t.Fatalf("mount %s: %v\nvault stderr tail:\n%s", mountPath, err, lastN(ringBuf.String(), 4000))
	}

	dv := &devVault{
		addr:    "http://" + addr,
		client:  client,
		cmd:     cmd,
		cleanup: cleanup,
	}

	if withAudit {
		dv.auditPath = filepath.Join(tmp, "audit.log")
		if err := client.Sys().EnableAuditWithOptionsWithContext(opCtx, "file", &vaultapi.EnableAuditOptions{
			Type: "file",
			Options: map[string]string{
				"file_path": dv.auditPath,
			},
		}); err != nil {
			cleanup()
			t.Fatalf("enable file audit at %s: %v", dv.auditPath, err)
		}
	}

	return dv
}

// TestAcceptance_full walks the §9.2 happy-path:
// mount → policy → hash → verify(correct, drift=false) → policy
// update → verify(drift=true) → delete → verify(404).
func TestAcceptance_full(t *testing.T) {
	dv := startDevVault(t, false)
	defer dv.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli := dv.client

	if _, err := cli.Logical().WriteWithContext(ctx, mountPath+"/policy/users", map[string]interface{}{
		"memory_kib":  32768,
		"iterations":  2,
		"parallelism": 1,
		"salt_len":    16,
		"key_len":     32,
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	hashResp, err := cli.Logical().WriteWithContext(ctx, mountPath+"/hash/users", map[string]interface{}{
		"password":   "correct horse battery staple",
		"subject_id": "u-1",
	})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if got, _ := hashResp.Data["hash_id"].(string); got != "u-1" {
		t.Errorf("hash_id: got %q, want u-1", got)
	}

	verifyOK, err := cli.Logical().WriteWithContext(ctx, mountPath+"/verify/u-1", map[string]interface{}{
		"password": "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("verify(correct): %v", err)
	}
	if got, _ := verifyOK.Data["valid"].(bool); !got {
		t.Error("verify(correct): valid=false, want true")
	}
	if got, _ := verifyOK.Data["policy_drift"].(bool); got {
		t.Error("verify(correct): drift=true with unchanged policy")
	}

	verifyBad, err := cli.Logical().WriteWithContext(ctx, mountPath+"/verify/u-1", map[string]interface{}{
		"password": "wrong",
	})
	if err != nil {
		t.Fatalf("verify(wrong): %v — wrong password must NOT be a 4xx error", err)
	}
	if got, _ := verifyBad.Data["valid"].(bool); got {
		t.Error("verify(wrong): valid=true on wrong password")
	}

	if _, err := cli.Logical().WriteWithContext(ctx, mountPath+"/policy/users", map[string]interface{}{
		"memory_kib":  65536,
		"iterations":  3,
		"parallelism": 2,
	}); err != nil {
		t.Fatalf("update policy: %v", err)
	}
	verifyDrift, err := cli.Logical().WriteWithContext(ctx, mountPath+"/verify/u-1", map[string]interface{}{
		"password": "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("verify(drift): %v", err)
	}
	if got, _ := verifyDrift.Data["valid"].(bool); !got {
		t.Error("verify(drift): valid=false; old hash should still verify after policy update")
	}
	if got, _ := verifyDrift.Data["policy_drift"].(bool); !got {
		t.Error("verify(drift): drift=false; should be true after policy update")
	}

	if _, err := cli.Logical().DeleteWithContext(ctx, mountPath+"/hash/u-1"); err != nil {
		t.Fatalf("delete hash: %v", err)
	}

	verifyGone, err := cli.Logical().WriteWithContext(ctx, mountPath+"/verify/u-1", map[string]interface{}{
		"password": "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("verify(deleted): %v", err)
	}
	if verifyGone != nil {
		t.Errorf("verify(deleted): expected nil secret for not-found, got %+v", verifyGone)
	}
}

// TestAcceptance_policyDeleteRejectsWhenReferenced confirms the
// §4.2 "policy DELETE 404s if hashes still reference it" guarantee
// holds end-to-end through the API.
func TestAcceptance_policyDeleteRejectsWhenReferenced(t *testing.T) {
	dv := startDevVault(t, false)
	defer dv.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli := dv.client

	if _, err := cli.Logical().WriteWithContext(ctx, mountPath+"/policy/users", nil); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if _, err := cli.Logical().WriteWithContext(ctx, mountPath+"/hash/users", map[string]interface{}{
		"password":   "p",
		"subject_id": "u-1",
	}); err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := cli.Logical().DeleteWithContext(ctx, mountPath+"/policy/users"); err == nil {
		t.Error("policy DELETE with referencing hash: expected error, got nil")
	}
	if _, err := cli.Logical().DeleteWithContext(ctx, mountPath+"/hash/u-1"); err != nil {
		t.Fatalf("delete hash: %v", err)
	}
	if _, err := cli.Logical().DeleteWithContext(ctx, mountPath+"/policy/users"); err != nil {
		t.Errorf("policy DELETE after hash cleanup: %v", err)
	}
}

// TestAcceptance_listReturnsIDsOnly confirms the LIST hash response
// carries no hash material, parameters, or password content.
func TestAcceptance_listReturnsIDsOnly(t *testing.T) {
	dv := startDevVault(t, false)
	defer dv.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli := dv.client

	if _, err := cli.Logical().WriteWithContext(ctx, mountPath+"/policy/users", nil); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	for _, id := range []string{"u-1", "u-2", "u-3"} {
		if _, err := cli.Logical().WriteWithContext(ctx, mountPath+"/hash/users", map[string]interface{}{
			"password":   "p",
			"subject_id": id,
		}); err != nil {
			t.Fatalf("hash %s: %v", id, err)
		}
	}

	listResp, err := cli.Logical().ListWithContext(ctx, mountPath+"/hash")
	if err != nil {
		t.Fatalf("list hash: %v", err)
	}
	if listResp == nil {
		t.Fatal("list hash: nil response")
	}
	keys, _ := listResp.Data["keys"].([]interface{})
	if len(keys) != 3 {
		t.Errorf("list keys: got %d, want 3", len(keys))
	}
	for _, forbidden := range []string{"phc", "password", "key", "salt", "parameters"} {
		if _, found := listResp.Data[forbidden]; found {
			t.Errorf("list response leaks %q field", forbidden)
		}
	}
}

// TestAcceptance_auditLogRedactsPassword writes a password through
// hash and verify with file-audit enabled, then scans the audit log
// to confirm the plaintext password never appears and that the
// non-secret fields (subject_id, hash_id, policy) do appear.
//
// This is the production-mode redaction guarantee, not a unit-test
// behavior — it depends on the framework recognizing
// DisplayAttributes.Sensitive on the password FieldSchema.
func TestAcceptance_auditLogRedactsPassword(t *testing.T) {
	dv := startDevVault(t, true)
	defer dv.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli := dv.client

	const sentinel = "REDACTION-CANARY-correct horse battery staple"

	if _, err := cli.Logical().WriteWithContext(ctx, mountPath+"/policy/users", nil); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if _, err := cli.Logical().WriteWithContext(ctx, mountPath+"/hash/users", map[string]interface{}{
		"password":   sentinel,
		"subject_id": "redaction-test-subject",
	}); err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := cli.Logical().WriteWithContext(ctx, mountPath+"/verify/redaction-test-subject", map[string]interface{}{
		"password": sentinel,
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Poll the audit log until it contains the verify request line
	// rather than sleeping a fixed interval. Fast runners exit
	// after the first poll; slow runners get up to 5s before the
	// test fails with a specific "audit log never landed" message.
	verifyMarker := []byte(mountPath + "/verify/")
	hashMarker := mountPath + "/hash/users"
	auditDeadline := time.Now().Add(5 * time.Second)
	var (
		raw    []byte
		readEr error
	)
	for time.Now().Before(auditDeadline) {
		raw, readEr = os.ReadFile(dv.auditPath)
		if readEr == nil && bytes.Contains(raw, verifyMarker) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if readEr != nil {
		t.Fatalf("read audit log: %v", readEr)
	}
	if !bytes.Contains(raw, verifyMarker) {
		t.Fatalf("audit log never received %s entry within 5s; size=%d", verifyMarker, len(raw))
	}

	// Sanity: the audit log MUST contain the non-secret fields,
	// otherwise we wouldn't be exercising the redaction surface.
	for _, want := range []string{"redaction-test-subject", hashMarker, string(verifyMarker)} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("audit log missing expected substring %q — test setup is broken", want)
		}
	}

	// Critical: the plaintext sentinel must NEVER appear. Vault
	// hashes sensitive fields by default (`hmac-sha256(...)`) when
	// the framework recognizes DisplayAttributes.Sensitive.
	if strings.Contains(string(raw), sentinel) {
		t.Errorf("audit log leaked plaintext password sentinel — DisplayAttributes.Sensitive redaction failed")
	}
}

// cachedPluginBinary builds the plugin once per `go test`
// invocation and caches the path. Subsequent callers receive the
// cached path. The build output lives outside any single test's
// t.TempDir so it survives across tests; tests still copy the
// binary into their own pluginDir before launching vault, since
// vault validates the plugin-dir's canonical path.
func cachedPluginBinary() (string, error) {
	pluginCacheOnce.Do(func() {
		repoRoot, err := os.Getwd()
		if err != nil {
			pluginCacheErr = fmt.Errorf("getwd: %w", err)
			return
		}
		dir, err := os.MkdirTemp("", "argon2-plugin-cache-")
		if err != nil {
			pluginCacheErr = fmt.Errorf("cache dir: %w", err)
			return
		}
		// Record the dir BEFORE the build runs so TestMain can clean
		// it up even if the build fails. Otherwise a `go build`
		// failure would leak the empty tempdir on every retry.
		pluginCacheDir = dir
		path := filepath.Join(dir, pluginName)
		build := exec.Command("go", "build", "-trimpath", "-o", path, "./cmd/"+pluginName)
		build.Dir = repoRoot
		if out, err := build.CombinedOutput(); err != nil {
			pluginCacheErr = fmt.Errorf("go build: %w\n%s", err, out)
			return
		}
		pluginCachePath = path
	})
	return pluginCachePath, pluginCacheErr
}

// copyFile copies src to dst with the given mode. dst is replaced
// if it already exists.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// sha256File returns the lowercase hex SHA-256 of the file at path.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// filterVaultEnv returns a copy of env with every VAULT_* entry
// removed. Used to make the dev-server subprocess hermetic against
// the developer's local environment — naming individual variables
// (ADDR/TOKEN/CACERT) would silently miss VAULT_NAMESPACE,
// VAULT_SKIP_VERIFY, VAULT_CLIENT_TIMEOUT, VAULT_TLS_*, etc.
func filterVaultEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "VAULT_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// freePort returns a TCP port that's currently free on 127.0.0.1.
// There is a TOCTOU window between this returning and the dev server
// binding — acceptable for local test usage; if collisions surface
// in CI, switch to letting Vault pick the port and parsing it back
// out of stderr.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("listener returned non-TCP addr")
	}
	return addr.Port, nil
}

// lastN returns at most the last n characters of s, useful for
// truncating subprocess stderr in failure messages.
func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
