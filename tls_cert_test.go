package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCertificate(t *testing.T, dir, domain string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "panel.crt"), filepath.Join(dir, "panel.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestCertificateReloaderChecksDomainAndSNI(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t, t.TempDir(), "panel.example.com")
	reloader, err := newCertificateReloader("panel.example.com", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloader.GetCertificate(clientHello("panel.example.com")); err != nil {
		t.Fatalf("matching SNI rejected: %v", err)
	}
	if _, err := reloader.GetCertificate(clientHello("other.example.com")); err == nil {
		t.Fatal("mismatched SNI was accepted")
	}
	if _, err := newCertificateReloader("other.example.com", certFile, keyFile); err == nil {
		t.Fatal("certificate for the wrong domain was accepted")
	}
}

func TestCertificateReloaderKeepsLastGoodPairDuringPartialRenewal(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestCertificate(t, dir, "panel.example.com")
	reloader, err := newCertificateReloader("panel.example.com", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reloader.GetCertificate(clientHello("panel.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, []byte("partial renewal"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := reloader.GetCertificate(clientHello("panel.example.com"))
	if err != nil {
		t.Fatalf("last good certificate was not retained: %v", err)
	}
	if got != first {
		t.Fatal("partial renewal replaced the cached certificate")
	}
}

func clientHello(serverName string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: serverName}
}
