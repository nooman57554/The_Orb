package keyloader

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	sharedkeyloader "github.com/nooman57554/The_Orb/orb_libs/identity/keyloader"
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
	if !sharedkeyloader.ValidKeyID(activeKeyID) {
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

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	publicKeys, err := sharedkeyloader.LoadPublicKeysFromDir(l.PublicKeysDir)
	if err != nil {
		return nil, fmt.Errorf("read public keys directory: %w", err)
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
