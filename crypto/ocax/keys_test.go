package cryptoocax

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyPairSignVerifyValid(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.PublicKey()
	fmt.Printf("privKey: %+v\n", privKey)
	data := []byte("Hello, world!")
	hash := crypto.Keccak256(data)
	if len(hash) != 32 {
		t.Fatalf("Unexpected hash length: got %v, want 32", len(hash))
	}

	sig, err := privKey.Sign(hash)
	assert.Nil(t, err)

	valid := sig.Verify(pubKey, hash)
	assert.True(t, valid)

}

func TestKeyPairSignVerifyFail(t *testing.T) {
	privKey1 := GeneratePrivateKey()

	privKey2 := GeneratePrivateKey()
	pubKey2 := privKey2.PublicKey()

	data := []byte("Hello, world!")
	hash := crypto.Keccak256(data)
	sig, err := privKey1.Sign(hash)
	require.NoError(t, err)

	valid := sig.Verify(pubKey2, hash)
	if valid {
		t.Error("The signature should be invalid, but verification succeeded")
	}
}

func TestSignatureToBytes(t *testing.T) {
	sig := Signature{
		R: big.NewInt(1234),
		S: big.NewInt(5678),
		V: big.NewInt(27),
	}
	bytes := sig.ToBytes()[:64]
	expected := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xd2,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x2e,
	}
	assert.Equal(t, expected, bytes)
}

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()

	if privKey.key == nil {
		t.Error("Generated private key is nil")
	}
}

func TestPublicKeyFromPrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.PublicKey()

	if len(pubKey) != 65 {
		t.Errorf("Unexpected public key length, expected 65, got %d", len(pubKey))
	}
}

func TestAddressFromPublicKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.PublicKey()
	address := PublicKey(pubKey).Address()
	fmt.Printf("address: %+v\n", address)
	if len(address) != 20 {
		t.Errorf("Unexpected address length, expected 20, got %d", len(address))
	}
}

func TestSign(t *testing.T) {
	privKey := GeneratePrivateKey()
	data := []byte("Sample message")
	hash := crypto.Keccak256(data)
	signature, err := privKey.Sign(hash)

	if err != nil {
		t.Errorf("Error signing data: %v", err)
	}

	if signature.R == nil || signature.S == nil || signature.V == nil {
		t.Error("Signature contains nil values")
	}
}

func TestSignatureStringAndToBytes(t *testing.T) {
	privKey := GeneratePrivateKey()
	data := []byte("Sample message")
	hash := crypto.Keccak256(data)
	signature, _ := privKey.Sign(hash)

	sigString := signature.String()
	sigBytes := signature.ToBytes()

	if len(sigString) == 0 {
		t.Error("Signature string is empty")
	}

	if len(sigBytes) != 65 {
		t.Errorf("Unexpected signature byte length, expected 65, got %d", len(sigBytes))
	}

	decodedSig, err := hex.DecodeString(sigString)
	if err != nil {
		t.Errorf("Error decoding signature string: %v", err)
	}

	if !bytes.Equal(decodedSig, sigBytes) {
		t.Error("Decoded signature string and ToBytes result do not match")
	}
}

func TestSignatureVerify(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.PublicKey()
	data := []byte("Sample message")
	hash := crypto.Keccak256(data)
	signature, _ := privKey.Sign(hash)

	verified := signature.Verify(pubKey, hash)

	if !verified {
		t.Error("Signature verification failed")
	}

	// Test with incorrect data
	incorrectData := []byte("Incorrect message")
	incorrectVerified := signature.Verify(pubKey, incorrectData)

	if incorrectVerified {
		t.Error("Signature verification passed with incorrect data")
	}
}
