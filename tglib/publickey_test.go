package tglib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return k
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return k
}

func selfSignedCert(t *testing.T, priv any, pub any) *pem.Block {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &pem.Block{Type: certificateHeader, Bytes: der}
}

func csrBlock(t *testing.T, priv any) *pem.Block {
	t.Helper()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return &pem.Block{Type: certificateRequestHeader, Bytes: der}
}

// PublicKeyToPEM

func TestPublicKeyToPEM_EC(t *testing.T) {
	key := generateECKey(t)
	block, err := PublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if block.Type != publicKeyHeader {
		t.Fatalf("want type %q, got %q", publicKeyHeader, block.Type)
	}
	got, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse back: %v", err)
	}
	if _, ok := got.(*ecdsa.PublicKey); !ok {
		t.Fatalf("want *ecdsa.PublicKey, got %T", got)
	}
}

func TestPublicKeyToPEM_RSA(t *testing.T) {
	key := generateRSAKey(t)
	block, err := PublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if block.Type != publicKeyHeader {
		t.Fatalf("want type %q, got %q", publicKeyHeader, block.Type)
	}
	got, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse back: %v", err)
	}
	if _, ok := got.(*rsa.PublicKey); !ok {
		t.Fatalf("want *rsa.PublicKey, got %T", got)
	}
}

func TestPublicKeyToPEM_Unsupported(t *testing.T) {
	_, err := PublicKeyToPEM("not-a-key")
	if err == nil {
		t.Fatal("want error for unsupported key type, got nil")
	}
}

// PEMToPublicKey

func TestPEMToPublicKey_PKIXPublicKey_EC(t *testing.T) {
	key := generateECKey(t)
	pemBlock, err := PublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatalf("PublicKeyToPEM: %v", err)
	}
	got, err := PEMToPublicKey(pemBlock)
	if err != nil {
		t.Fatalf("PEMToPublicKey: %v", err)
	}
	if _, ok := got.(*ecdsa.PublicKey); !ok {
		t.Fatalf("want *ecdsa.PublicKey, got %T", got)
	}
}

func TestPEMToPublicKey_PKCS1PublicKey_RSA(t *testing.T) {
	key := generateRSAKey(t)
	der := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	block := &pem.Block{Type: rsaPublicKeyHeader, Bytes: der}
	got, err := PEMToPublicKey(block)
	if err != nil {
		t.Fatalf("PEMToPublicKey: %v", err)
	}
	if _, ok := got.(*rsa.PublicKey); !ok {
		t.Fatalf("want *rsa.PublicKey, got %T", got)
	}
}

func TestPEMToPublicKey_Certificate_EC(t *testing.T) {
	key := generateECKey(t)
	block := selfSignedCert(t, key, key.Public())
	got, err := PEMToPublicKey(block)
	if err != nil {
		t.Fatalf("PEMToPublicKey: %v", err)
	}
	if _, ok := got.(*ecdsa.PublicKey); !ok {
		t.Fatalf("want *ecdsa.PublicKey, got %T", got)
	}
}

func TestPEMToPublicKey_Certificate_RSA(t *testing.T) {
	key := generateRSAKey(t)
	block := selfSignedCert(t, key, key.Public())
	got, err := PEMToPublicKey(block)
	if err != nil {
		t.Fatalf("PEMToPublicKey: %v", err)
	}
	if _, ok := got.(*rsa.PublicKey); !ok {
		t.Fatalf("want *rsa.PublicKey, got %T", got)
	}
}

func TestPEMToPublicKey_CertificateRequest_EC(t *testing.T) {
	key := generateECKey(t)
	block := csrBlock(t, key)
	got, err := PEMToPublicKey(block)
	if err != nil {
		t.Fatalf("PEMToPublicKey: %v", err)
	}
	if _, ok := got.(*ecdsa.PublicKey); !ok {
		t.Fatalf("want *ecdsa.PublicKey, got %T", got)
	}
}

func TestPEMToPublicKey_CertificateRequest_RSA(t *testing.T) {
	key := generateRSAKey(t)
	block := csrBlock(t, key)
	got, err := PEMToPublicKey(block)
	if err != nil {
		t.Fatalf("PEMToPublicKey: %v", err)
	}
	if _, ok := got.(*rsa.PublicKey); !ok {
		t.Fatalf("want *rsa.PublicKey, got %T", got)
	}
}

func TestPEMToPublicKey_ECPublicKey_Panics(t *testing.T) {
	key := generateECKey(t)
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal EC public key: %v", err)
	}
	block := &pem.Block{Type: ecPublicKeyHeader, Bytes: der}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("want panic for ecPublicKeyHeader, got none")
		}
	}()
	_, _ = PEMToPublicKey(block)
}

func TestPEMToPublicKey_InvalidBytes(t *testing.T) {
	for _, typ := range []string{publicKeyHeader, rsaPublicKeyHeader, certificateHeader, certificateRequestHeader} {
		block := &pem.Block{Type: typ, Bytes: []byte("garbage")}
		_, err := PEMToPublicKey(block)
		if err == nil {
			t.Errorf("type %q: want error for corrupt bytes, got nil", typ)
		}
	}
}

func TestPEMToPublicKey_UnsupportedType(t *testing.T) {
	block := &pem.Block{Type: "UNKNOWN KEY", Bytes: []byte{}}
	_, err := PEMToPublicKey(block)
	if err == nil {
		t.Fatal("want error for unknown PEM type, got nil")
	}
}

// PublicKeyFromPrivate

func TestPublicKeyFromPrivate_ECDSA(t *testing.T) {
	key := generateECKey(t)
	pub, err := PublicKeyFromPrivate(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("want *ecdsa.PublicKey, got %T", pub)
	}
}

func TestPublicKeyFromPrivate_RSA(t *testing.T) {
	key := generateRSAKey(t)
	pub, err := PublicKeyFromPrivate(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("want *rsa.PublicKey, got %T", pub)
	}
}

func TestPublicKeyFromPrivate_Unsupported(t *testing.T) {
	_, err := PublicKeyFromPrivate("not-a-private-key")
	if err == nil {
		t.Fatal("want error for unsupported key type, got nil")
	}
}
