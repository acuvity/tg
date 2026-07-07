package tglib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// EncryptStringAES encrypt the given string
func EncryptStringAES(value string, passphrase []byte) (string, error) {

	if value == "" {
		return "", nil
	}

	data := []byte(value)

	c, err := aes.NewCipher(passphrase)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, data, nil)), nil
}

// DecryptStringAES decrypts the given string.
func DecryptStringAES(value string, passphrase []byte) (string, error) {

	if value == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}

	c, err := aes.NewCipher(passphrase)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("data is too small")
	}

	out, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}

	return string(out), nil
}
