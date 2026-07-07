package tglib

import (
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptAESGCM(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte("hello aes-gcm")

	ciphertext, err := EncryptStringAES(string(plaintext), key)
	if err != nil {
		t.Fatalf("EncryptStringAES: %v", err)
	}

	got, err := DecryptStringAES(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptStringAES: %v", err)
	}

	if got != string(plaintext) {
		t.Fatalf("want %q, got %q", plaintext, got)
	}
}
