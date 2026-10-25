package keyloader_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/nooman57554/The_Orb/orb_libs/identity/keyloader"
)

func generateEd25519PEM(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), pub
}

func TestLoadPublicKeysFromDir_Valid(t *testing.T) {
	tempDir := t.TempDir()

	pem1, pub1 := generateEd25519PEM(t)
	pem2, pub2 := generateEd25519PEM(t)

	if err := os.WriteFile(filepath.Join(tempDir, "key-1.pem"), pem1, 0600); err != nil {
		t.Fatalf("write key-1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "key-2.pem"), pem2, 0600); err != nil {
		t.Fatalf("write key-2: %v", err)
	}
	// Non-PEM file should be ignored
	if err := os.WriteFile(filepath.Join(tempDir, "README.txt"), []byte("notes"), 0600); err != nil {
		t.Fatalf("write readme: %v", err)
	}

	keys, err := keyloader.LoadPublicKeysFromDir(tempDir)
	if err != nil {
		t.Fatalf("LoadPublicKeysFromDir failed: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if !ed25519.PublicKey(keys["key-1"]).Equal(pub1) {
		t.Errorf("key-1 does not match expected public key")
	}
	if !ed25519.PublicKey(keys["key-2"]).Equal(pub2) {
		t.Errorf("key-2 does not match expected public key")
	}
}

func TestLoadPublicKeysFromDir_MalformedPEM(t *testing.T) {
	tempDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tempDir, "bad-key.pem"), []byte("NOT A VALID PEM"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := keyloader.LoadPublicKeysFromDir(tempDir)
	if err == nil {
		t.Fatal("expected error for malformed PEM, got nil")
	}
}

func TestLoadPublicKeysFromDir_UnsupportedKeyType(t *testing.T) {
	tempDir := t.TempDir()

	// Generate RSA key instead of Ed25519
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal rsa key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})

	if err := os.WriteFile(filepath.Join(tempDir, "rsa-key.pem"), pemBytes, 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err = keyloader.LoadPublicKeysFromDir(tempDir)
	if err == nil {
		t.Fatal("expected error for unsupported RSA public key, got nil")
	}
}

func TestLoadPublicKeysFromDir_InvalidKeyID(t *testing.T) {
	tempDir := t.TempDir()

	pemBytes, _ := generateEd25519PEM(t)
	// Spaces are not allowed in key ID
	if err := os.WriteFile(filepath.Join(tempDir, "invalid key id.pem"), pemBytes, 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := keyloader.LoadPublicKeysFromDir(tempDir)
	if err == nil {
		t.Fatal("expected error for invalid key ID in filename, got nil")
	}
}

func TestLoadPublicKeysFromDir_EmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()

	_, err := keyloader.LoadPublicKeysFromDir(tempDir)
	if err == nil {
		t.Fatal("expected error for empty directory, got nil")
	}
}

func TestLoadPublicKeysFromDir_NonExistentDir(t *testing.T) {
	_, err := keyloader.LoadPublicKeysFromDir(filepath.Join(t.TempDir(), "non-existent-dir"))
	if err == nil {
		t.Fatal("expected error for non-existent directory, got nil")
	}
}

func TestLoadPublicKeysFromDir_EmptyParam(t *testing.T) {
	_, err := keyloader.LoadPublicKeysFromDir("")
	if err == nil {
		t.Fatal("expected error for empty directory parameter, got nil")
	}
}

func TestParsePublicKeyPEM_TrailingData(t *testing.T) {
	pemBytes, _ := generateEd25519PEM(t)
	withTrailing := append(pemBytes, []byte("unexpected extra trailing data")...)

	_, err := keyloader.ParsePublicKeyPEM(withTrailing)
	if err == nil {
		t.Fatal("expected error for trailing data after PEM block, got nil")
	}
}

func TestParsePublicKeyPEM_WrongBlockType(t *testing.T) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("dummy-bytes"),
	}
	pemBytes := pem.EncodeToMemory(block)

	_, err := keyloader.ParsePublicKeyPEM(pemBytes)
	if err == nil {
		t.Fatal("expected error for non-PUBLIC KEY block type, got nil")
	}
}

func TestValidKeyID(t *testing.T) {
	tests := []struct {
		keyID string
		want  bool
	}{
		{keyID: "key-1", want: true},
		{keyID: "key_2024_01", want: true},
		{keyID: "key.rsa", want: true},
		{keyID: "KEY-ABC", want: true},
		{keyID: "", want: false},
		{keyID: ".", want: false},
		{keyID: "..", want: false},
		{keyID: "key with space", want: false},
		{keyID: "key/slash", want: false},
		{keyID: "key\\backslash", want: false},
		{keyID: "key:colon", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.keyID, func(t *testing.T) {
			got := keyloader.ValidKeyID(tc.keyID)
			if got != tc.want {
				t.Errorf("ValidKeyID(%q) = %v, want %v", tc.keyID, got, tc.want)
			}
		})
	}
}
