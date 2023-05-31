package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
)

func TestTransaction(t *testing.T) {
	privateKey := cryptoocax.GeneratePrivateKey()
	pubKey := privateKey.PublicKey()
	from := pubKey.Address()
	data := *randomRFQ(t)
	inner := &RFQRequest{
		From: from,
		Data: data,
	}

	tx := NewTx(inner)
	assert.Equal(t, from, *tx.inner.from())
	// 0x00 is the type ID for RFQRequestTxType
	dataBytes := tx.inner.data()
	var dataRfq SignableRFQData
	err := json.Unmarshal(dataBytes, &dataRfq)
	assert.Nil(t, err)

	assert.Equal(t, data.RequestorId, dataRfq.RequestorId)

	assert.Equal(t, uint8(0x00), tx.inner.txType())

	signedTx, err := tx.Sign(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)
	assert.NotNil(t, signedTx)
	assert.Equal(t, &from, signedTx.inner.from())
	// assert.Equal(t, []byte("Hello, world!"), signedTx.inner.data())
	r, s, v := signedTx.inner.rawSignatureValues()
	assert.NotNil(t, r)
	assert.NotNil(t, s)
	assert.NotNil(t, v)
}

func TestSignTransaction(t *testing.T) {
	key := cryptoocax.GeneratePrivateKey()
	from := key.PublicKey().Address()

	// prepare Signer
	// data := []byte("foobar")

	txData := &RFQRequest{
		From: from,
		Data: *randomRFQ(t),
	}

	tx := NewTx(txData)

	signed, err := tx.Sign(key)
	assert.Nil(t, err)
	assert.NotNil(t, signed)
	assert.Equal(t, &from, signed.From())
}

func TestVerifyTransaction(t *testing.T) {
	privKey := cryptoocax.GeneratePrivateKey()
	pubKey := privKey.PublicKey()

	from := pubKey.Address()
	// signer := NewSigner()
	data := *randomRFQ(t)

	txData := &RFQRequest{
		From: from,
		Data: data,
	}

	tx := NewTx(txData)
	signedTx, err := tx.Sign(privKey)
	assert.Nil(t, err)
	// Wrong Address
	txSender, err := tx.Sender()
	assert.Nil(t, err)
	assert.Equal(t, from, txSender)
	assert.Equal(t, signedTx.From(), &txData.From)
	v, r, s := signedTx.RawSignatureValues()
	sig := &cryptoocax.Signature{R: r, S: s, V: v}

	verified := sig.Verify(pubKey, signedTx.Hash().Bytes())
	assert.True(t, verified)
}

func TestRFQRequestEncodeDecode(t *testing.T) {
	req := &RFQRequest{
		From: common.Address{},
		Data: *randomRFQ(t),
		V:    big.NewInt(1),
		R:    big.NewInt(1),
		S:    big.NewInt(1),
	}

	var buffer bytes.Buffer
	err := req.EncodeRLP(&buffer)
	if err != nil {
		t.Fatalf("Failed to encode RFQRequest: %v", err)
	}

	var decodedReq RFQRequest
	s := rlp.NewStream(&buffer, 0)
	err = decodedReq.DecodeRLP(s)
	if err != nil {
		t.Fatalf("Failed to decode RFQRequest: %v", err)
	}

	// Check if decodedReq matches req
}

func TestTransactionEncodeDecode(t *testing.T) {
	// create a transaction

	var (
		signer     = NewSigner()
		privateKey = cryptoocax.GeneratePrivateKey()
		pubKey     = privateKey.PublicKey()
		from       = pubKey.Address()
	)

	txData := &RFQRequest{
		From: from,
		Data: *randomRFQ(t),
	}

	tx, err := SignNewTx(&privateKey, signer, txData)
	if err != nil {
		t.Fatalf("could not sign transaction: %v", err)
	}

	// RLP

	var buffer bytes.Buffer
	err = tx.EncodeRLP(&buffer)
	if err != nil {
		t.Fatal(err)
	}

	var decodedReq RFQRequest
	s := rlp.NewStream(&buffer, 0)
	err = decodedReq.DecodeRLP(s)
	if err != nil {
		t.Fatalf("Failed to decode RFQRequest: %v", err)
	}
}

func encodeDecodeBinary(tx *Transaction) (*Transaction, error) {
	// tx.EncodeRLP()

	data, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("rlp encoding failed: %v", err)
	}
	var parsedTx = &Transaction{}
	if err := parsedTx.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("rlp decoding failed: %v", err)
	}
	return parsedTx, nil
}

func encodeDecodeJSON(tx *Transaction) (*Transaction, error) {
	data, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %v", err)
	}
	var parsedTx = &Transaction{}
	if err := json.Unmarshal(data, &parsedTx); err != nil {
		return nil, fmt.Errorf("json decoding failed: %v", err)
	}
	return parsedTx, nil
}

func assertEqual(orig *Transaction, cpy *Transaction) error {
	// Compare each field of the transaction, reporting any discrepancies
	if want, got := orig.From(), cpy.From(); !bytes.Equal(want.Bytes(), got.Bytes()) {
		return fmt.Errorf("parsed tx 'From' field differs from original tx, want %v, got %v", want, got)
	}

	if want, got := orig.Data(), cpy.Data(); !bytes.Equal(want, got) {
		return fmt.Errorf("parsed tx 'Data' field differs from original tx, want %v, got %v", want, got)
	}

	ov, or, os := orig.RawSignatureValues()
	cv, cr, cs := cpy.RawSignatureValues()
	fmt.Println("ov, or, os: ", ov, or, os)
	fmt.Println("cv, cr, cs: ", cv, cr, cs)
	if wantV, wantR, wantS := orig.RawSignatureValues(); wantV != nil && wantR != nil && wantS != nil {
		gotV, gotR, gotS := cpy.RawSignatureValues()
		if gotV != nil && gotR != nil && gotS != nil {
			if want, got := wantV, gotV; want.Cmp(got) != 0 {
				return fmt.Errorf("parsed tx 'V' field differs from original tx, want %v, got %v", want, got)
			}

			if want, got := wantR, gotR; want.Cmp(got) != 0 {
				return fmt.Errorf("parsed tx 'R' field differs from original tx, want %v, got %v", want, got)
			}

			if want, got := wantS, gotS; want.Cmp(got) != 0 {
				return fmt.Errorf("parsed tx 'S' field differs from original tx, want %v, got %v", want, got)
			}
		} else {
			return fmt.Errorf("one of the signature fields (V, R, S) in the parsed transaction is nil")
		}
	} else {
		return fmt.Errorf("one of the signature fields (V, R, S) in the original transaction is nil")
	}
	if want, got := orig.Hash(), cpy.Hash(); want != got {
		return fmt.Errorf("parsed tx differs from original tx, want %v, got %v", want, got)
	}

	return nil
}

// func TestTxEncodeDecode(t *testing.T) {
// 	privKey := crypto.GeneratePrivateKey()
// 	tx := randomTxWithSignature(t, privKey)

// 	buf := &bytes.Buffer{}

// 	enc := NewRLPTxEncoder(buf)
// 	assert.Nil(t, enc.Encode(tx))

// 	decTx := new(Transaction)
// 	assert.Nil(t, decTx.Decode(NewRLPTxDecoder(buf)))
// 	assert.True(t, tx.Equal(decTx))

// }

func randomTxWithSignature(t *testing.T, key cryptoocax.PrivateKey) *Transaction {
	pubKey := key.PublicKey()
	from := pubKey.Address()
	inner := &RFQRequest{
		From: from,
		Data: *randomRFQ(t),
	}

	tx := NewTx(inner)

	signedTx, err := tx.Sign(key)
	assert.Nil(t, err)

	return signedTx
}
