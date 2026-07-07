package tglib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const minRSABits = 3072

// EncryptAsym encrypts plaintext with a random AES key, then RSA-OAEP
// wraps that key. Returns a base64(encryptedKey).base64(ciphertext) string.
func EncryptAsym(plaintext []byte, rsaPublicKey *rsa.PublicKey) (string, error) {

	if rsaPublicKey.N.BitLen() < minRSABits {
		return "", fmt.Errorf("invalid RSA public key size: %d bits, minimum is %d", rsaPublicKey.N.BitLen(), minRSABits)
	}
	randomAESKey := make([]byte, 32)
	if _, err := rand.Read(randomAESKey); err != nil {
		return "", fmt.Errorf("generate aes key: %w", err)
	}

	ciphertext, err := EncryptStringAES(string(plaintext), randomAESKey)
	if err != nil {
		return "", fmt.Errorf("encrypt plaintext: %w", err)
	}

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, randomAESKey, nil)
	if err != nil {
		return "", fmt.Errorf("encrypt aes key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedKey) + "." + ciphertext, nil
}

// DecryptAsym reverses EncryptAsym using the RSA private key.
// token must be in the base64(encryptedKey).ciphertext format returned by EncryptAsym.
func DecryptAsym(token string, rsaPrivateKey *rsa.PrivateKey) ([]byte, error) {

	encodedKey, ciphertext, ok := strings.Cut(token, ".")
	if !ok {
		return nil, fmt.Errorf("invalid token format")
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted key: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt aes key: %w", err)
	}

	plaintext, err := DecryptStringAES(ciphertext, aesKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt plaintext: %w", err)
	}

	return []byte(plaintext), nil
}
