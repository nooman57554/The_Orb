package keyloader

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadPublicKeysFromDir reads all .pem public key files from dir and returns a map
// of key ID to ed25519.PublicKey. The key ID is the filename without the .pem extension.
func LoadPublicKeysFromDir(dir string) (map[string]ed25519.PublicKey, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("public keys directory is required")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read public keys directory: %w", err)
	}

	publicKeys := make(map[string]ed25519.PublicKey)

	for _, entry := range entries {
		// Only .pem files are treated as public keys.
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}

		keyID := strings.TrimSuffix(entry.Name(), ".pem")
		if !ValidKeyID(keyID) {
			return nil, fmt.Errorf("invalid public key filename: %q", entry.Name())
		}

		if _, exists := publicKeys[keyID]; exists {
			return nil, fmt.Errorf("duplicate public key ID: %q", keyID)
		}

		path := filepath.Join(dir, entry.Name())
		publicKey, err := LoadPublicKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("load public key %q: %w", keyID, err)
		}

		publicKeys[keyID] = publicKey
	}

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("no public keys found in %q", dir)
	}

	return publicKeys, nil
}

// LoadPublicKeyFile reads and parses a single Ed25519 public key from a PEM-encoded file.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	return ParsePublicKeyPEM(data)
}

// ParsePublicKeyPEM parses an Ed25519 public key from PEM-encoded bytes.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("unexpected data after PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected PKIX PUBLIC KEY PEM block, got %q", block.Type)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}

	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key must be Ed25519, got %T", parsed)
	}

	return append(ed25519.PublicKey(nil), key...), nil
}

// ValidKeyID validates whether a key ID contains only allowed characters and is non-empty.
func ValidKeyID(keyID string) bool {
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
