package cryptoocax

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type PrivateKey struct {
	key *ecdsa.PrivateKey
}

func (k PrivateKey) ToECDSAPublic() *ecdsa.PublicKey {
	pubKey := k.key.Public()
	publicKeyECSDA, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		panic("not ok")
	}
	return publicKeyECSDA
}

func (k PrivateKey) Sign(data []byte) (*Signature, error) {
	sig, err := crypto.Sign(data, k.key)
	if err != nil {
		return nil, err
	}
	if len(sig) != 65 {
		return nil, errors.New("invalid signature length")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := sig[64]

	if v != 0 && v != 1 {
		return nil, errors.New("invalid recovery id")
	}
	// Adjust the recovery id to be 27 or 28
	// v += 27
	vBigInt := new(big.Int).SetInt64(int64(v))
	return &Signature{R: r, S: s, V: vBigInt}, nil
}

func GeneratePrivateKey() PrivateKey {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return PrivateKey{key: key}
}

func (k PrivateKey) ToBytes() []byte {
	return crypto.FromECDSA(k.key)
}

func (k PrivateKey) PublicKey() PublicKey {
	return elliptic.Marshal(k.ToECDSAPublic().Curve, k.ToECDSAPublic().X, k.ToECDSAPublic().Y)
}

type PublicKey []byte

func (k PublicKey) ToECDSAPublic() *ecdsa.PublicKey {
	key, err := crypto.UnmarshalPubkey(k)
	if err != nil {
		panic(err)
	}
	return key
}

func (k PublicKey) ToHex() string {
	bytePubKey := elliptic.Marshal(k.ToECDSAPublic().Curve, k.ToECDSAPublic().X, k.ToECDSAPublic().Y)
	return hex.EncodeToString(bytePubKey)
}

func (k PublicKey) Address() common.Address {
	pubKey, _ := crypto.UnmarshalPubkey([]byte(k))
	ethAddress := crypto.PubkeyToAddress(*pubKey).Hex()
	ocaxAddress := common.HexToAddress(ethAddress)
	return ocaxAddress
}

func (pk PublicKey) Verify(data []byte, sig Signature) bool {
	hash := crypto.Keccak256(data)
	validate := validate(pk, sig.ToBytes(), hash)

	return validate
}

func Keccak256Hash(data []byte) []byte {
	return crypto.Keccak256(data)
}

type Signature struct {
	V, R, S *big.Int
}

func (sig *Signature) String() string {
	return hex.EncodeToString(sig.ToBytes())
}

func (sig *Signature) ToBytes() []byte {
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	vByte := byte(sig.V.Int64())

	// Ensure R and S are 32 bytes long each
	RBytesPadded := make([]byte, 32)
	SBytesPadded := make([]byte, 32)

	copy(RBytesPadded[32-len(rBytes):], rBytes)
	copy(SBytesPadded[32-len(sBytes):], sBytes)

	// Combine R, S and V
	signature := append(RBytesPadded, SBytesPadded...)
	signature = append(signature, vByte)

	return signature
}

func DeserializeSig(sigBytes []byte) (*Signature, error) {
	if len(sigBytes) != 65 {
		return nil, errors.New("invalid signature length")
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])
	v := new(big.Int).SetInt64(int64(sigBytes[64]))

	return &Signature{R: r, S: s, V: v}, nil
}

func DeserializeSigFromHexString(sigHex string) (*Signature, error) {
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, err
	}
	return DeserializeSig(sigBytes)
}

func PrivateKeyFromBytes(privKeyBytes []byte) (*PrivateKey, error) {
	privKeyECDSA, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: privKeyECDSA}, nil
}

func BytesToPublicKey(pubKeyBytes []byte) (PublicKey, error) {
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y), nil
}

func (sig *Signature) Verify(pubkey PublicKey, data []byte) bool {
	validate := validate(pubkey, sig.ToBytes(), data)

	return validate
}

func validate(ecdsaPubBytes []byte, signature []byte, messageHash []byte) bool {
	return crypto.VerifySignature(ecdsaPubBytes, messageHash, signature[:64])
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
func ValidateSignatureValues(v byte, r, s *big.Int) bool {
	homestead := false
	return crypto.ValidateSignatureValues(v, r, s, homestead)
}

func Ecrecover(hash, sig []byte) ([]byte, error) {
	return crypto.Ecrecover(hash, sig)
}
