package types

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	ErrInvalidSig         = errors.New("invalid transaction v, r, s values")
	ErrInvalidTxType      = errors.New("transaction type not valid in this context")
	ErrTxTypeNotSupported = errors.New("transaction type not supported")
	errShortTypedTx       = errors.New("typed transaction too short")
)

const (
	RFQRequestTxType    = 0x00
	QuoteTxType         = 0x01
	AuctionRecordTxType = 0x02
)

type AuctionRecord struct{}

type Transaction struct {
	inner TxData
	time  time.Time

	// caching
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

func NewTx(inner TxData) *Transaction {
	tx := new(Transaction)
	tx.setDecoded(inner.copy(), 0)
	return tx
}

type TxData interface {
	from() *common.Address // sender of the transaction
	txType() byte          // returns the type ID
	copy() TxData          // creates a deep copy and initializes all fields

	data() []byte

	rawSignatureValues() (v, r, s *big.Int)
	setSignatureValues(v, r, s *big.Int)
}

func (tx *Transaction) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, tx.inner)
}

// encodeTyped writes the canonical encoding of a typed transaction to w.
func (tx *Transaction) encodeTyped(w *bytes.Buffer) error {
	w.WriteByte(tx.Type())
	return rlp.Encode(w, tx.inner)
}

// MarshalBinary returns the canonical encoding of the transaction.
// For legacy transactions, it returns the RLP encoding. For EIP-2718 typed
// transactions, it returns the type and payload.
func (tx *Transaction) MarshalBinary() ([]byte, error) {
	if tx.Type() == RFQRequestTxType {
		return rlp.EncodeToBytes(tx.inner)
	}
	var buf bytes.Buffer
	err := tx.encodeTyped(&buf)
	return buf.Bytes(), err
}

func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	var txData RFQRequest
	if err := s.Decode(&txData); err != nil {
		return err
	}

	tx.inner = &txData
	return nil
}

// UnmarshalBinary decodes the canonical encoding of transactions.
// It supports legacy RLP transactions and EIP2718 typed transactions.
func (tx *Transaction) UnmarshalBinary(b []byte) error {
	var data RFQRequest
	if data.V == nil {
		data.V = new(big.Int)
	}
	if data.R == nil {
		data.R = new(big.Int)
	}
	if data.S == nil {
		data.S = new(big.Int)
	}
	err := rlp.DecodeBytes(b, &data)
	if err != nil {
		return err
	}
	tx.setDecoded(&data, uint64(len(b)))
	return nil
}

// decodeTyped decodes a typed transaction from the canonical format.
func (tx *Transaction) decodeTyped(b []byte) (TxData, error) {
	if len(b) <= 1 {
		return nil, errShortTypedTx
	}
	fmt.Printf("b[0]: %+v\n", b[0])
	switch b[0] {
	case RFQRequestTxType:
		var inner RFQRequest
		err := rlp.DecodeBytes(b[1:], &inner)
		return &inner, err
	case QuoteTxType:
		var inner Quote
		err := rlp.DecodeBytes(b[1:], &inner)
		return &inner, err
	default:
		return nil, ErrTxTypeNotSupported
	}
}

// setDecoded sets the inner transaction and size after decoding.
func (tx *Transaction) setDecoded(inner TxData, size uint64) {
	tx.inner = inner
	tx.time = time.Now()
	if size > 0 {
		tx.size.Store(size)
	}
}

// Type returns the transaction type.
func (tx *Transaction) Type() uint8 {
	return tx.inner.txType()
}

func (tx *Transaction) From() *common.Address {
	if tx.inner == nil {
		return nil
	}
	return copyAddressPtr(tx.inner.from())
}

// Data returns the input data of the transaction.
func (tx *Transaction) Data() []byte { return tx.inner.data() }

// RawSignatureValues returns the V, R, S signature values of the transaction.
// The return values should not be modified by the caller.
func (tx *Transaction) RawSignatureValues() (v, r, s *big.Int) {
	return tx.inner.rawSignatureValues()
}

// func (tx *Transaction) ByteSignatureValues() []byte {
// 	_, r, s := tx.inner.rawSignatureValues()

// 	signature := append(r.Bytes(), s.Bytes()...)

// 	return signature

// }

// Hash returns the transaction hash.
func (tx *Transaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}

	v, r, s := tx.inner.rawSignatureValues()

	h := rlpHash([]interface{}{
		tx.inner.from(),
		tx.inner.data(),
		v,
		r,
		s,
	})
	// h := prefixedRlpHash(tx.Type(), tx.inner)
	tx.hash.Store(h)
	return h
}

// Size returns the true encoded storage size of the transaction, either by encoding
// and returning it, or returning a previously cached value.
func (tx *Transaction) Size() uint64 {
	if size := tx.size.Load(); size != nil {
		return size.(uint64)
	}
	c := writeCounter(0)
	rlp.Encode(&c, &tx.inner)

	size := uint64(c)

	tx.size.Store(size)
	return size
}

// WithSignature returns a new transaction with the given signature.
// This signature needs to be in the [R || S || V] format where V is 0 or 1.
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := tx.inner.copy()
	cpy.setSignatureValues(v, r, s)
	return &Transaction{inner: cpy, time: tx.time}, nil
}

// Transactions implements DerivableList for transactions.
type Transactions []*Transaction

// Len returns the length of s.
func (s Transactions) Len() int { return len(s) }

// EncodeIndex encodes the i'th transaction to w. Note that this does not check for errors
// because we assume that *Transaction will only ever contain valid txs that were either
// constructed by decoding or via public API in this package.
func (s Transactions) EncodeIndex(i int, w *bytes.Buffer) {
	tx := s[i]
	tx.encodeTyped(w)
}

// // Transactions impleme
func (tx *Transaction) Sign(privKey cryptoocax.PrivateKey) (*Transaction, error) {
	sig, err := privKey.Sign(tx.Hash().Bytes())
	if err != nil {
		return &Transaction{}, err
	}
	tx.inner.setSignatureValues(sig.V, sig.R, sig.S)
	hash := tx.Hash()
	size := tx.Size()

	signedTx := &Transaction{
		inner: tx.inner,
		time:  tx.time,
	}
	signedTx.hash.Store(hash)
	signedTx.size.Store(size)

	return signedTx, nil
}

func (tx *Transaction) Sender() (common.Address, error) {
	return *tx.From(), nil
}

func (tx *Transaction) Verify() error {
	v, r, s := tx.inner.rawSignatureValues()
	if r == nil || s == nil || v == nil {
		return fmt.Errorf("no signature - invalid transaction")
	}

	sig := &cryptoocax.Signature{R: r, S: s, V: v}

	if !cryptoocax.ValidateSignatureValues(byte(v.Uint64()), r, s) {
		return fmt.Errorf("invalid signature values")
	}

	hash := tx.Hash() // Calculate the transaction hash here.
	recoveredPubKey, err := cryptoocax.Ecrecover(hash.Bytes(), sig.ToBytes())
	if err != nil {
		return fmt.Errorf("failed to recover public key: %v", err)
	}

	pubKey, err := crypto.UnmarshalPubkey(recoveredPubKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %v", err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	fromAddress := tx.inner.from()
	if fromAddress == nil {
		return fmt.Errorf("no from address")
	}

	if !bytes.Equal(fromAddress.Bytes(), recoveredAddr.Bytes()) {
		return fmt.Errorf("signature does not match sender's public key")
	}

	return nil
}

// func (tx *Transaction) Decode(dec Decoder[*Transaction]) error {
// 	return dec.Decode(tx)
// }

// func (tx *Transaction) Encode(enc Encoder[*Transaction]) error {
// 	return enc.Encode(tx)
// }

// copyAddressPtr copies an address.
func copyAddressPtr(a *common.Address) *common.Address {
	if a == nil {
		return nil
	}
	cpy := *a
	return &cpy
}

// Len returns the length of s.
// func (s types.Transactions) Len() int { return len(s) }

// EncodeIndex encodes the i'th transaction to w. Note that this does not check for errors
// because we assume that *Transaction will only ever contain valid txs that were either
// constructed by decoding or via public API in this package.
// func (s types.Transactions) EncodeIndex(i int, w *bytes.Buffer) {
// 	tx := s[i]
// 	tx.encodeTyped(w)
// }
