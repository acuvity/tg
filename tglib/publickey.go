package tglib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PublicKeyToPEM converts the given crypto.PublicKey to a *pem.Block.
func PublicKeyToPEM(key crypto.PublicKey) (*pem.Block, error) {

	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal public key: %w", err)
	}

	return &pem.Block{
		Type:  publicKeyHeader,
		Bytes: b,
	}, nil
}

// PEMToPublicKey loads a PEM block and returns a crypto.PublicKey.
func PEMToPublicKey(keyBlock *pem.Block) (crypto.PublicKey, error) {

	switch keyBlock.Type {

	case publicKeyHeader:
		return x509.ParsePKIXPublicKey(keyBlock.Bytes)

	case rsaPublicKeyHeader:
		return x509.ParsePKCS1PublicKey(keyBlock.Bytes)

	default:
		return nil, fmt.Errorf("unsupported public key type: %s", keyBlock.Type)
	}
}

// PublicKeyFromPrivate extracts the crypto.PublicKey from any supported private key.
func PublicKeyFromPrivate(priv crypto.PrivateKey) (crypto.PublicKey, error) {

	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	case *rsa.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}
