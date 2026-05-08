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
// Prerequisites: a `vault` binary on PATH (any 1.20+ release works;
// the test pins root-token-id=root and reads VAULT_ADDR locally).
//
// Run with: make acceptance — or `go test -tags acceptance ./...`.
// The build tag keeps `go test ./...` (and `go test -short`) cheap.

package argon2id_test

import (
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
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

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

	// Build the plugin binary into pluginDir/<pluginName>.
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	pluginPath := filepath.Join(pluginDir, pluginName)
	build := exec.Command("go", "build", "-trimpath", "-o", pluginPath, "./cmd/"+pluginName)
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build plugin: %v\n%s", err, out)
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
		"-log-level=warn",
	)
	// Don't inherit VAULT_* env vars from the parent — the test must
	// be hermetic against the developer's environment.
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR=",
		"VAULT_TOKEN=",
		"VAULT_CACERT=",
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
	// the last 200 lines for failure diagnostics.
	var ringBuf strings.Builder
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				ringBuf.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	cleanup := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
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

	deadline := time.Now().Add(devStartTimeout)
	for time.Now().Before(deadline) {
		health, err := client.Sys().Health()
		if err == nil && health != nil && health.Initialized && !health.Sealed {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, err := client.Sys().Health(); err != nil {
		cleanup()
		t.Fatalf("vault never became ready (last %d bytes of stderr):\n%s", len(ringBuf.String()), ringBuf.String())
	}

	// Register the plugin in the catalog and mount it. Dev mode
	// auto-discovers binaries in -dev-plugin-dir but does not
	// auto-register them under our chosen plugin name — register
	// explicitly with the SHA we computed.
	if err := client.Sys().RegisterPluginWithContext(context.Background(), &vaultapi.RegisterPluginInput{
		Name:    pluginName,
		Type:    vaultapi.PluginTypeSecrets,
		Command: pluginName,
		SHA256:  sum,
	}); err != nil {
		cleanup()
		t.Fatalf("register plugin: %v", err)
	}

	if err := client.Sys().Mount(mountPath, &vaultapi.MountInput{
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
		if err := client.Sys().EnableAuditWithOptions("file", &vaultapi.EnableAuditOptions{
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

	ctx := context.Background()
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

	ctx := context.Background()
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

	ctx := context.Background()
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

	ctx := context.Background()
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

	// Vault's file audit device flushes synchronously, but give it
	// a beat to settle on slow CI runners.
	time.Sleep(300 * time.Millisecond)

	raw, err := os.ReadFile(dv.auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("audit log empty — Vault did not flush")
	}

	// Sanity: the audit log MUST contain the non-secret fields,
	// otherwise we wouldn't be exercising the redaction surface.
	for _, want := range []string{"redaction-test-subject", "argon2/hash/users", "argon2/verify/"} {
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
