package types

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
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
	errInvalidAddress     = errors.New("invalid Ethereum address")
	errInvalidChecksum    = errors.New("invalid Ethereum address checksum")
	errInvalidSymbol      = errors.New("invalid token symbol")
	errInvalidDecimals    = errors.New("invalid token decimals")
	errInvalidAmount      = errors.New("invalid token amount")
	errInvalidDuration    = errors.New("invalid RFQ duration")
	errInvalidRequestorId = errors.New("invalid requestor ID")
	errInvalidTimestamp   = errors.New("invalid timestamp")
)

const (
	RFQRequestTxType = 0x00
	OpenRFQTxType    = 0x01
	ClosedRFQTxType  = 0x02
	MatchedRFQTxType = 0x03
	SettledRFQTxType = 0x04
	QuoteTxType      = 0x05
)

type Transaction struct {
	inner TxData
	time  time.Time

	// caching
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

func NewTx(inner TxData) *Transaction {
	tx := &Transaction{
		inner: inner,
	}
	tx.setDecoded(inner.copy(), 0)
	return tx
}

type TxData interface {
	from() *common.Address // sender of the transaction
	txType() byte          // returns the type ID
	copy() TxData          // creates a deep copy and initializes all fields

	data() []byte

	rfqData() *SignableData

	rawSignatureValues() (v, r, s *big.Int)
	setSignatureValues(v, r, s *big.Int)
	referenceTxHash() common.Hash // add this
}

func (tx *Transaction) EncodeRLP(w io.Writer) error {
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(buf)
	buf.Reset()
	if err := tx.encodeTyped(buf); err != nil {
		return err
	}
	return rlp.Encode(w, buf.Bytes())
}

// transactions, it returns the type and payload.
func (tx *Transaction) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	err := tx.encodeTyped(&buf)
	return buf.Bytes(), err
}

func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	var b []byte
	var err error

	if b, err = s.Bytes(); err != nil {
		return err
	}

	fmt.Printf("Decoding transaction. Length: %d\n", len(b)) // Debug output

	inner, err := tx.decodeTyped(b)
	if err == nil {
		tx.setDecoded(inner, uint64(len(b)))
	}
	return err
}

// encodeTyped writes the canonical encoding of a typed transaction to w.
func (tx *Transaction) encodeTyped(w *bytes.Buffer) error {
	w.WriteByte(tx.Type())
	return rlp.Encode(w, tx.inner)
}

// UnmarshalBinary decodes the canonical encoding of transactions.
// It supports legacy RLP transactions and EIP2718 typed transactions.
func (tx *Transaction) UnmarshalBinary(b []byte) error {
	inner, err := tx.decodeTyped(b)
	if err != nil {
		return err
	}
	tx.setDecoded(inner, uint64(len(b)))
	return nil
}

// decodeTyped decodes a typed transaction from the canonical format.
func (tx *Transaction) decodeTyped(b []byte) (TxData, error) {
	if len(b) <= 1 {
		fmt.Println("len(b) <= 1 ", len(b))
		return nil, errShortTypedTx
	}

	switch b[0] {
	case RFQRequestTxType:
		var inner RFQRequest
		fmt.Printf("Trying to decode RFQRequest. Bytes: %v\n", b[1:])
		err := rlp.DecodeBytes(b[1:], &inner)
		// err := rlp.DecodeBytes(b[1:], &inner)
		return &inner, err
	case OpenRFQTxType:
		var inner OpenRFQ
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

// decodeTyped decodes a ty
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

func (tx *Transaction) ReferenceTxHash() common.Hash {
	return tx.inner.referenceTxHash()
}

func (tx *Transaction) RFQData() *SignableData {
	return tx.inner.rfqData()
}

// RawSignatureValues returns the V, R, S signature values of the transaction.
// The return values should not be modified by the caller.
func (tx *Transaction) RawSignatureValues() (v, r, s *big.Int) {
	return tx.inner.rawSignatureValues()
}

// Hash returns the transaction hash.
func (tx *Transaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	fmt.Printf("Hashing transaction. Type: %d, Data: %#v\n", tx.Type(), tx.inner)
	h := prefixedRlpHash(tx.Type(), tx.inner.data())
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
	fmt.Printf("TX hash: %+v\n", hash.Hex())
	fmt.Printf("Tx data: %+v\n", tx.inner)
	recoveredPubKey, err := cryptoocax.Ecrecover(hash.Bytes(), sig.ToBytes())
	if err != nil {
		return fmt.Errorf("failed to recover public key: %v", err)
	}

	pubKey, err := crypto.UnmarshalPubkey(recoveredPubKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %v", err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	fmt.Printf("recoveredAddr: %+v\n", recoveredAddr)
	fromAddress := tx.inner.from()
	if fromAddress == nil {
		return fmt.Errorf("no from address")
	}

	if !bytes.Equal(fromAddress.Bytes(), recoveredAddr.Bytes()) {
		return fmt.Errorf("signature does not match sender's public key")
	}

	return nil
}

func (tx *Transaction) String() string {
	v, r, s := tx.inner.rawSignatureValues()

	dataString := "<unprintable>"
	if stringer, ok := tx.inner.(fmt.Stringer); ok {
		dataString = stringer.String()
	}

	return fmt.Sprintf(`Transaction{
		Type: %d,
		From: %s,
		Data: %s,
		V: %s,
		R: %s,
		S: %s
	}`,
		tx.inner.txType(),
		tx.inner.from().String(),
		dataString,
		v.String(),
		r.String(),
		s.String(),
	)
}

func (tx *Transaction) Validate() error {

	// validate the signature

	if err := tx.Verify(); err != nil {
		return err
	}

	if err := tx.validateRequestorId(); err != nil {
		return err
	}

	if err := validateAddress(*tx.From()); err != nil {
		return err
	}

	if err := tx.RFQData().Validate(); err != nil {
		return err
	}

	// Repeat similar validations for other fields...
	return nil
}

// validateRequestorId validates the requestor ID field.
func (r *Transaction) validateRequestorId() error {
	// Logic here to validate the requestor ID field
	// match, _ := regexp.MatchString("^[0-9]+$", r.RequestorId)
	// if !match {
	// 	return errInvalidRequestorId
	// }
	return nil
}

// validateAddress validates that the given string is a valid Ethereum address.
func validateAddress(addr common.Address) error {
	if !common.IsHexAddress(addr.String()) {
		return errInvalidAddress
	}

	// check if the address has mixed case, then it should be checksum
	if hasMixedCase(addr.String()) && !common.IsHexAddress(addr.Hex()) {
		return errInvalidChecksum
	}

	return nil
}

// helper function to determine if the address has mixed case
func hasMixedCase(s string) bool {
	return strings.ToLower(s) != s && strings.ToUpper(s) != s
}

// copyAddressPtr copies an address.
func copyAddressPtr(a *common.Address) *common.Address {
	if a == nil {
		return nil
	}
	cpy := *a
	return &cpy
}
