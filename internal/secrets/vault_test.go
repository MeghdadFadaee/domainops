package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultRoundTripLockAndWrongPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "vault.json")
	vault, err := New(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !vault.Locked() {
		t.Fatal("new vault should start locked")
	}
	password := []byte("correct horse battery staple")
	if err := vault.Unlock(context.Background(), password); err != nil {
		t.Fatal(err)
	}
	first, err := vault.Put(context.Background(), "", []byte("token-one"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := vault.Put(context.Background(), "", []byte("token-two"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first == "" || second == "" {
		t.Fatalf("secret references must be unique: %q %q", first, second)
	}
	value, err := vault.Get(context.Background(), first)
	if err != nil || string(value) != "token-one" {
		t.Fatalf("get first secret = %q, %v", value, err)
	}
	vault.Lock()
	if _, err := vault.Get(context.Background(), first); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked Get error = %v", err)
	}
	if err := vault.Unlock(context.Background(), []byte("definitely wrong")); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("wrong password error = %v", err)
	}
	if err := vault.Unlock(context.Background(), password); err != nil {
		t.Fatal(err)
	}
	value, err = vault.Get(context.Background(), second)
	if err != nil || string(value) != "token-two" {
		t.Fatalf("persisted second secret = %q, %v", value, err)
	}
	if err := vault.Delete(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Get(context.Background(), first); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("deleted secret error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode = %o", info.Mode().Perm())
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if parent.Mode().Perm() != 0o700 {
		t.Fatalf("vault parent mode = %o", parent.Mode().Perm())
	}
}

func TestVaultRejectsTamperingAndSymlinks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "vault.json")
	vault, err := New(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("a long test password")
	if err := vault.Unlock(context.Background(), password); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Put(context.Background(), "ref", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	vault.Lock()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(body) / 2; i < len(body); i++ {
		if body[i] >= 'A' && body[i] <= 'Z' {
			body[i] = 'a'
			break
		}
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	tampered, err := New(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tampered.Unlock(context.Background(), password); err == nil {
		t.Fatal("tampered vault unexpectedly unlocked")
	}

	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link, "", ""); err == nil {
		t.Fatal("symlink vault unexpectedly accepted")
	}
}

func TestVaultHonorsCancelledContext(t *testing.T) {
	vault, err := New(filepath.Join(t.TempDir(), "vault.json"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := vault.Unlock(ctx, []byte("long enough password")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Unlock error = %v", err)
	}
}

func TestVaultTracksPostRenamePutAndDeleteOutcomes(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vault.json")
	vault, err := New(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("long durability password")
	if err := vault.Unlock(ctx, password); err != nil {
		t.Fatal(err)
	}
	injectCommittedError := func(envelope diskEnvelope) error {
		if err := vault.writeEnvelope(envelope); err != nil {
			return err
		}
		return &committedEnvelopeError{err: errors.New("injected directory sync failure")}
	}
	vault.writeEnvelopeOverride = injectCommittedError
	reference, err := vault.Put(ctx, "committed-ref", []byte("secret"))
	if reference != "committed-ref" || err == nil {
		t.Fatalf("post-rename Put = ref:%q err:%v", reference, err)
	}
	if value, getErr := vault.Get(ctx, reference); getErr != nil || string(value) != "secret" {
		t.Fatalf("in-memory committed Put = %q, %v", value, getErr)
	}
	vault.writeEnvelopeOverride = nil
	vault.Lock()
	if err := vault.Unlock(ctx, password); err != nil {
		t.Fatal(err)
	}
	if value, getErr := vault.Get(ctx, reference); getErr != nil || string(value) != "secret" {
		t.Fatalf("on-disk committed Put = %q, %v", value, getErr)
	}

	vault.writeEnvelopeOverride = injectCommittedError
	if err := vault.Delete(ctx, reference); err == nil {
		t.Fatal("post-rename Delete did not report durability failure")
	}
	if _, getErr := vault.Get(ctx, reference); !errors.Is(getErr, ErrSecretNotFound) {
		t.Fatalf("in-memory committed Delete = %v", getErr)
	}
	if err := vault.Delete(ctx, reference); err != nil {
		t.Fatalf("idempotent delete did not retry directory durability: %v", err)
	}
	vault.writeEnvelopeOverride = nil
	vault.Lock()
	if err := vault.Unlock(ctx, password); err != nil {
		t.Fatal(err)
	}
	if _, getErr := vault.Get(ctx, reference); !errors.Is(getErr, ErrSecretNotFound) {
		t.Fatalf("on-disk committed Delete = %v", getErr)
	}
}
