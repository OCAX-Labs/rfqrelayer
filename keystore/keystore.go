package keystore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize   = 32
	nonceSize = 24
)

type EncryptedKey struct {
	Nonce  [nonceSize]byte
	Secret []byte
}

type KeyStore struct {
	PrivateKey *cryptoocax.PrivateKey
}

func NewKeyStore() *KeyStore {
	return &KeyStore{}
}

// This function generates a new key, encrypts it using the passphrase,
// and stores the encrypted key in a file.
func (k *KeyStore) GenerateKeyToFile(passphrase, filePath string) error {
	key := cryptoocax.GeneratePrivateKey()
	k.PrivateKey = &key
	return k.SaveKeyToFile(passphrase, filePath)
}

// This function encrypts the key using the passphrase and stores it in a file.
func (k *KeyStore) SaveKeyToFile(passphrase, filePath string) error {
	if k.PrivateKey == nil {
		return errors.New("private key is not set")
	}

	secret := k.PrivateKey.ToBytes()
	if len(secret) != keySize {
		return errors.New("private key has unexpected size")
	}

	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}

	// var key [keySize]byte
	key := createKeyFromPassphrase(passphrase)
	// copy(key[:], passphrase)

	encrypted := secretbox.Seal(nonce[:], secret, &nonce, &key)

	encryptedKey := &EncryptedKey{
		Secret: encrypted,
	}

	fmt.Printf("encryptedKey: %v\n", encryptedKey)
	data, err := json.Marshal(encryptedKey)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, data, 0600)
}

// This function reads the key from the file, decrypts it using the passphrase,
// and stores it in the KeyStore.
func (k *KeyStore) LoadKeyFromFile(passphrase, filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var encryptedKey EncryptedKey
	if err := json.Unmarshal(data, &encryptedKey); err != nil {
		return err
	}

	// var key [keySize]byte
	key := createKeyFromPassphrase(passphrase)
	// copy(key[:], pass)

	var decryptNonce [nonceSize]byte
	copy(decryptNonce[:], encryptedKey.Secret[:nonceSize])

	decrypted, ok := secretbox.Open(nil, encryptedKey.Secret[nonceSize:], &decryptNonce, &key)
	if !ok {
		return errors.New("could not decrypt the key, possibly because the passphrase is incorrect")
	}

	privateKey, err := cryptoocax.PrivateKeyFromBytes(decrypted)
	if err != nil {
		return err
	}

	k.PrivateKey = privateKey

	return nil
}
func createKeyFromPassphrase(passphrase string) [32]byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash
}
