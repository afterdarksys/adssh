package security

import (
	"context"
	"strings"
	"testing"
)

func TestParseLeaseSourceSpec(t *testing.T) {
	path, query, err := parseLeaseSourceSpec("secret/data/app?field=password&region=us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if path != "secret/data/app" {
		t.Fatalf("path = %q", path)
	}
	if query.Get("field") != "password" || query.Get("region") != "us-east-1" {
		t.Fatalf("query = %#v", query)
	}
}

func TestExtractLeaseSecretValueSupportsVaultKV2(t *testing.T) {
	secret, err := extractLeaseSecretValue("vault", map[string]interface{}{
		"data": map[string]interface{}{
			"password": "vault-secret",
			"username": "alice",
		},
	}, "password")
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "vault-secret" {
		t.Fatalf("secret = %q", secret)
	}
}

func TestExtractLeaseSecretValueRequiresFieldForAmbiguousMap(t *testing.T) {
	_, err := extractLeaseSecretValue("vault", map[string]interface{}{
		"alpha": "one",
		"bravo": "two",
	}, "")
	if err == nil || !strings.Contains(err.Error(), "multiple fields") {
		t.Fatalf("expected multiple fields error, got %v", err)
	}
}

func TestLoadLeaseSecretDispatchesVaultBackedSource(t *testing.T) {
	original := leaseSecretReaders["vault"]
	leaseSecretReaders["vault"] = func(_ context.Context, spec string) ([]byte, error) {
		if spec != "secret/data/app?field=password" {
			t.Fatalf("spec = %q", spec)
		}
		return []byte("vault-secret"), nil
	}
	defer func() { leaseSecretReaders["vault"] = original }()

	secret, err := loadLeaseSecret(context.Background(), "vault:secret/data/app?field=password")
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "vault-secret" {
		t.Fatalf("secret = %q", secret)
	}
}
