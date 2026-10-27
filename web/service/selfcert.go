package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"x-ui/config"
)

// SelfSignedServerName is the name the self-signed certificate is issued for;
// share links carry it as SNI together with insecure=1.
const SelfSignedServerName = "www.bing.com"

var selfCertLock sync.Mutex

// GetSelfSignedCert returns the panel's self-signed certificate, creating it
// on first use, so inbounds that require TLS work without a domain.
func (s *ServerService) GetSelfSignedCert() (map[string]any, error) {
	selfCertLock.Lock()
	defer selfCertLock.Unlock()

	dir := filepath.Join(config.GetDBFolderPath(), "cert")
	certFile := filepath.Join(dir, "self-signed.crt")
	keyFile := filepath.Join(dir, "self-signed.key")

	der, err := readCertDER(certFile)
	if err != nil {
		if der, err = writeSelfSignedCert(dir, certFile, keyFile); err != nil {
			return nil, err
		}
	} else if _, statErr := os.Stat(keyFile); statErr != nil {
		if der, err = writeSelfSignedCert(dir, certFile, keyFile); err != nil {
			return nil, err
		}
	}
	sum := sha256.Sum256(der)
	return map[string]any{
		"certFile":   certFile,
		"keyFile":    keyFile,
		"serverName": SelfSignedServerName,
		"sha256":     hex.EncodeToString(sum[:]),
	}, nil
}

func readCertDER(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	if _, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	}
	return block.Bytes, nil
}

func writeSelfSignedCert(dir, certFile, keyFile string) ([]byte, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: SelfSignedServerName},
		DNSNames:              []string{SelfSignedServerName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return der, nil
}
