package types

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/ethereum/go-ethereum/crypto"
)

// SignatureLength indicates the byte length required to carry a signature with recovery id.
const SignatureLength = 64 + 1 // 64 bytes ECDSA signature + 1 byte recovery id

// RecoveryIDOffset points to the byte offset within the signature that contains the recovery id.
const RecoveryIDOffset = 64

// DigestLength sets the signature digest exact length
const DigestLength = 32

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
type sigCache struct {
	signer Signer
	from   common.Address
}

// SignTx signs the transaction using the given signer and private key.
func SignTx(tx *Transaction, s Signer, prv *cryptoocax.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	sig, err := prv.Sign(h[:])
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig.ToBytes())
}

// SignNewTx creates a transaction and signs it.
func SignNewTx(prv *cryptoocax.PrivateKey, s Signer, txdata TxData) (*Transaction, error) {
	tx := NewTx(txdata)
	h := tx.Hash()
	sig, err := prv.Sign(h[:])

	if err != nil {
		return nil, err
	}
	signature := append(sig.R.Bytes(), sig.S.Bytes()...)
	signature = append(signature, byte(sig.V.Uint64()))

	return tx.WithSignature(s, signature)
}

// Sender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, tx *Transaction) (common.Address, error) {
	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}
	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	fmt.Printf("signer : %+v from ADDRESSS %+v   \n", signer, addr)
	tx.from.Store(sigCache{signer: signer, from: addr})
	return addr, nil
}

// Signer encapsulates transaction signature handling. The name of this type is slightly
// misleading because Signers don't actually sign, they're just for validating and
// processing of signatures.
type Signer interface {
	// Sender returns the sender public key of the given transaction.
	Sender(tx *Transaction) (common.Address, error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	// ChainID() *big.Int

	// Hash returns 'signature hash', i.e. the transaction hash that is signed by the
	// private key. This hash does not uniquely identify the transaction.
	Hash(tx *Transaction) common.Hash

	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
}

type txSigner struct{}

func NewSigner() Signer {
	signer := &txSigner{}
	return signer
}

func (tx txSigner) Sender(tr *Transaction) (common.Address, error) {

	V, R, S := tr.RawSignatureValues()

	return recoverPlain(tx.Hash(tr), R, S, V, false)
}

func (tx txSigner) Hash(tr *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tr.From(),
		tr.Data(),
	})
}

func (ts txSigner) Equal(s2 Signer) bool {
	_, ok := s2.(txSigner)
	return ok
}

func (ts txSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	if len(sig) != SignatureLength {
		return nil, nil, nil, ErrInvalidSig
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v, nil
}

func SignatureToBytes(R, S *big.Int, V byte) []byte {
	RBytes := R.Bytes()
	SBytes := S.Bytes()

	// Ensure R and S are 32 bytes long each
	RBytesPadded := make([]byte, 32)
	SBytesPadded := make([]byte, 32)

	copy(RBytesPadded[32-len(RBytes):], RBytes)
	copy(SBytesPadded[32-len(SBytes):], SBytes)

	// Combine R, S and V
	signature := append(RBytesPadded, SBytesPadded...)
	signature = append(signature, V)

	return signature
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int, homestead bool) (common.Address, error) {
	if Vb.BitLen() > 8 {
		return common.Address{}, ErrInvalidSig
	}

	V := byte(Vb.Uint64() - 27)
	if !cryptoocax.ValidateSignatureValues(V, R, S) {
		panic("invalid signature values")
		// return common.Address{}, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}

	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

func publicKeyFromBytes(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256() // Replace with the curve you are using
	pointSize := (curve.Params().BitSize + 7) / 8

	if len(pubKeyBytes) != 2*pointSize+1 {
		return nil, fmt.Errorf("invalid public key length")
	}

	if pubKeyBytes[0] != 4 {
		return nil, fmt.Errorf("invalid public key format, expected uncompressed format (0x04)")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(pubKeyBytes[1 : pointSize+1]),
		Y:     new(big.Int).SetBytes(pubKeyBytes[pointSize+1:]),
	}

	return pubKey, nil
}
