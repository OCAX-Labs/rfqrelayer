package keystore

import (
	"bytes"
	"os"
	"testing"

	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
)

const (
	testFilePath = "testfile.json"
	testPass     = "testpassphrase"
)

func TestGenerateKeyToFile(t *testing.T) {
	ks := NewKeyStore()

	err := ks.GenerateKeyToFile(testPass, testFilePath)
	if err != nil {
		t.Fatalf("Failed to generate key to file: %v", err)
	}

	_, err = os.Stat(testFilePath)
	if err != nil {
		t.Fatalf("File was not created: %v", err)
	}

	if ks.PrivateKey == nil {
		t.Fatalf("Private key was not set in KeyStore")
	}

	// cleanup
	os.Remove(testFilePath)
}

func TestSaveKeyToFile(t *testing.T) {
	ks := NewKeyStore()
	privateKey := cryptoocax.GeneratePrivateKey()
	ks.PrivateKey = &privateKey

	err := ks.SaveKeyToFile(testPass, testFilePath)
	if err != nil {
		t.Fatalf("Failed to save key to file: %v", err)
	}

	_, err = os.Stat(testFilePath)
	if err != nil {
		t.Fatalf("File was not created: %v", err)
	}

	// cleanup
	os.Remove(testFilePath)
}

func TestLoadKeyFromFile(t *testing.T) {
	ks := NewKeyStore()
	privateKey := cryptoocax.GeneratePrivateKey()
	ks.PrivateKey = &privateKey

	err := ks.SaveKeyToFile(testPass, testFilePath)
	if err != nil {
		t.Fatalf("Failed to save key to file: %v", err)
	}

	ks2 := NewKeyStore()
	err = ks2.LoadKeyFromFile(testPass, testFilePath)
	if err != nil {
		t.Fatalf("Failed to load key from file: %v", err)
	}

	if ks2.PrivateKey == nil {
		t.Fatalf("Private key was not set in KeyStore")
	}

	// Compare original and loaded private keys
	if !bytes.Equal(ks.PrivateKey.ToBytes(), ks2.PrivateKey.ToBytes()) {
		t.Fatalf("Original and loaded private keys do not match")
	}

	// cleanup
	os.Remove(testFilePath)
}
