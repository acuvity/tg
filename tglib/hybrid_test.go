package tglib

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return priv
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	priv := generateTestKey(t)
	plaintext := []byte("my-secret-provider-token")

	token, err := EncryptAsym(plaintext, &priv.PublicKey)
	if err != nil {
		t.Fatalf("EncryptAsym: %v", err)
	}

	got, err := DecryptAsym(token, priv)
	if err != nil {
		t.Fatalf("DecryptAsym: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Fatalf("want %q, got %q", plaintext, got)
	}
}
