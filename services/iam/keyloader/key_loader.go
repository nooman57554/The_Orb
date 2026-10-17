package keyloader

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type KeySet struct {
	ActiveKeyID string
	PrivateKey  ed25519.PrivateKey
	PublicKeys  map[string]ed25519.PublicKey
}

type KeyLoader interface {
	Load(ctx context.Context) (*KeySet, error)
}

// FileLoader loads an Ed25519 key pair from PEM files.
type FileLoader struct {
	PrivateKeyPath string
	PublicKeyPath  string
	KeyID          string
}

var _ KeyLoader = (*FileLoader)(nil)

func NewFileLoader(
	privateKeyPath string,
	publicKeyPath string,
	keyID string,
) (*FileLoader, error) {
	if privateKeyPath == "" || publicKeyPath == "" || keyID == "" {
		return nil, fmt.Errorf(
			"private key path, public key path, and key ID are required",
		)
	}

	return &FileLoader{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		KeyID:          keyID,
	}, nil
}

func (l *FileLoader) Load(ctx context.Context) (*KeySet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	privatePEM, err := os.ReadFile(l.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	publicPEM, err := os.ReadFile(l.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	privateBlock, _ := pem.Decode(privatePEM)
	if privateBlock == nil {
		return nil, fmt.Errorf("decode private key PEM: no PEM block found")
	}

	parsedPrivate, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	privateKey, ok := parsedPrivate.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be Ed25519")
	}

	publicBlock, _ := pem.Decode(publicPEM)
	if publicBlock == nil {
		return nil, fmt.Errorf("decode public key PEM: no PEM block found")
	}

	parsedPublic, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	publicKey, ok := parsedPublic.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key must be Ed25519")
	}

	// Ensure the public key actually corresponds to the private key.
	derivedPublic := privateKey.Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(derivedPublic, publicKey) != 1 {
		return nil, fmt.Errorf("private key and public key do not match")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &KeySet{
		ActiveKeyID: l.KeyID,
		PrivateKey:  privateKey,
		PublicKeys: map[string]ed25519.PublicKey{
			l.KeyID: publicKey,
		},
	}, nil
}
