package keyloader

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type KeySet struct {
	ActiveKeyID string
	PrivateKey  ed25519.PrivateKey
	PublicKeys  map[string]ed25519.PublicKey
}

type KeyLoader interface {
	Load(ctx context.Context) (*KeySet, error)
}

type FileLoader struct {
	PrivateKeyPath string
	PublicKeysDir  string
	ActiveKeyID    string
}

var _ KeyLoader = (*FileLoader)(nil)

func NewFileLoader(
	privateKeyPath string,
	publicKeysDir string,
	activeKeyID string,
) (*FileLoader, error) {
	if strings.TrimSpace(privateKeyPath) == "" {
		return nil, fmt.Errorf("private key path is required")
	}
	if strings.TrimSpace(publicKeysDir) == "" {
		return nil, fmt.Errorf("public keys directory is required")
	}
	if !validKeyID(activeKeyID) {
		return nil, fmt.Errorf("invalid active key ID")
	}

	return &FileLoader{
		PrivateKeyPath: privateKeyPath,
		PublicKeysDir:  publicKeysDir,
		ActiveKeyID:    activeKeyID,
	}, nil
}

func (l *FileLoader) Load(ctx context.Context) (*KeySet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	privateKey, err := loadPrivateKey(l.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load active private key: %w", err)
	}

	entries, err := os.ReadDir(l.PublicKeysDir)
	if err != nil {
		return nil, fmt.Errorf("read public keys directory: %w", err)
	}

	publicKeys := make(map[string]ed25519.PublicKey)

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Only PEM files are treated as public keys.
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}

		keyID := strings.TrimSuffix(entry.Name(), ".pem")
		if !validKeyID(keyID) {
			return nil, fmt.Errorf("invalid public key filename: %q", entry.Name())
		}

		if _, exists := publicKeys[keyID]; exists {
			return nil, fmt.Errorf("duplicate public key ID: %q", keyID)
		}

		path := filepath.Join(l.PublicKeysDir, entry.Name())

		publicKey, err := loadPublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("load public key %q: %w", keyID, err)
		}

		publicKeys[keyID] = publicKey
	}

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("no public keys found in %q", l.PublicKeysDir)
	}

	activePublicKey, exists := publicKeys[l.ActiveKeyID]
	if !exists {
		return nil, fmt.Errorf(
			"active key ID %q has no matching public key",
			l.ActiveKeyID,
		)
	}

	derivedPublicKey := privateKey.Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(derivedPublicKey, activePublicKey) != 1 {
		return nil, fmt.Errorf(
			"active private key does not match public key %q",
			l.ActiveKeyID,
		)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &KeySet{
		ActiveKeyID: l.ActiveKeyID,
		PrivateKey:  privateKey,
		PublicKeys:  publicKeys,
	}, nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("unexpected data after PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected PKCS#8 PRIVATE KEY PEM block")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}

	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be Ed25519")
	}

	return append(ed25519.PrivateKey(nil), key...), nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("unexpected data after PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected PKIX PUBLIC KEY PEM block")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}

	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key must be Ed25519")
	}

	return append(ed25519.PublicKey(nil), key...), nil
}

func validKeyID(keyID string) bool {
	if keyID == "" || len(keyID) > 128 {
		return false
	}

	for _, r := range keyID {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.') {
			return false
		}
	}

	return keyID != "." && keyID != ".."
}
