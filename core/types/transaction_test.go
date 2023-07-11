package types

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"testing"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	quoteAddress = common.HexToAddress("0x9fB29AAc15b9A4B7F17c3385939b007540f4d791")
	quoteSig     = &cryptoocax.Signature{R: big.NewInt(1), S: big.NewInt(1), V: big.NewInt(28)}
)

func TestBaseTokenRLPEncoding(t *testing.T) {
	token := &BaseToken{
		Address:  common.HexToAddress("0x1234567890"),
		Symbol:   "ABC",
		Decimals: 18,
	}

	// Encode the token using rlp.Encode
	encoded, err := rlp.EncodeToBytes(token)
	require.NoError(t, err)

	// Decode the encoded bytes into a new BaseToken using rlp.Decode
	decoded := &BaseToken{}
	err = rlp.DecodeBytes(encoded, decoded)
	require.NoError(t, err)

	require.Equal(t, token.Address, decoded.Address)
	require.Equal(t, token.Symbol, decoded.Symbol)
	require.Equal(t, token.Decimals, decoded.Decimals)
}

func TestSignableDataRLPEncoding(t *testing.T) {
	addr1 := cryptoocax.GeneratePrivateKey().PublicKey().Address()
	addr2 := cryptoocax.GeneratePrivateKey().PublicKey().Address()

	baseToken := &BaseToken{
		Address:  addr1,
		Symbol:   "ABC",
		Decimals: 18,
	}

	quoteToken := &QuoteToken{
		Address:  addr2,
		Symbol:   "XYZ",
		Decimals: 18,
	}

	rfqData := &SignableData{
		RequestorId:     "123",
		BaseTokenAmount: big.NewInt(1000),
		BaseToken:       baseToken,
		QuoteToken:      quoteToken,
		RFQDurationMs:   uint64(5000),
	}

	// encodedBuffer := new(bytes.Buffer)
	rfqBytes, err := rlp.EncodeToBytes(rfqData)
	// err := rfqData.EncodeToBytes(encodedBuffer)
	require.NoError(t, err)
	encoded := bytes.NewReader(rfqBytes)

	// // Calculate the expected encoded byte slice
	// expectedEncoded, err := rlp.EncodeToBytes(rfqData)
	// require.NoError(t, err)

	// Compare the actual encoded byte slice with the expected encoded byte slice
	fmt.Println("encoded hex: ", hex.EncodeToString(rfqBytes))
	// Decode the RLP-encoded byte slice into a new SignableData struct
	// decoded := new(SignableData)
	// s := rlp.NewStream(ioutil.NopCloser(bytes.NewReader(encoded.)), uint64(len(encoded)))
	var decoded SignableData
	if err := rlp.Decode(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("decoded: %#v\n", decoded)
	require.NoError(t, err)

	// Perform assertions to ensure the decoded instance matches the original data
	assert.Equal(t, rfqData.RequestorId, decoded.RequestorId)
	assert.Equal(t, rfqData.BaseTokenAmount, decoded.BaseTokenAmount)
	assert.Equal(t, rfqData.BaseToken.Address, decoded.BaseToken.Address)
	assert.Equal(t, rfqData.BaseToken.Symbol, decoded.BaseToken.Symbol)
	assert.Equal(t, rfqData.BaseToken.Decimals, decoded.BaseToken.Decimals)
	assert.Equal(t, rfqData.QuoteToken.Address, decoded.QuoteToken.Address)
	assert.Equal(t, rfqData.QuoteToken.Symbol, decoded.QuoteToken.Symbol)
	assert.Equal(t, rfqData.QuoteToken.Decimals, decoded.QuoteToken.Decimals)
	assert.Equal(t, rfqData.RFQDurationMs, decoded.RFQDurationMs)
}
func TestTransaction(t *testing.T) {
	privateKey := cryptoocax.GeneratePrivateKey()
	pubKey := privateKey.PublicKey()
	from := pubKey.Address()
	data := randomRFQ(t)
	inner := &RFQRequest{
		From: from,
		Data: randomRFQ(t),
	}

	tx := NewTx(inner)
	assert.Equal(t, from, *tx.inner.from())
	// 0x00 is the type ID for RFQRequestTxType
	dataBytes := tx.inner.data()
	var dataRfq SignableData
	if err := rlp.DecodeBytes(dataBytes, &dataRfq); err != nil {
		t.Fatal(err)
	}

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
		Data: randomRFQ(t),
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
	data := randomRFQ(t)

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

func TestRFQRequestRLPEncoding(t *testing.T) {
	// Create a sample RFQRequest
	privateKey := cryptoocax.GeneratePrivateKey()
	publicKey := privateKey.PublicKey()
	from := publicKey.Address()

	addr1 := cryptoocax.GeneratePrivateKey().PublicKey().Address()
	addr2 := cryptoocax.GeneratePrivateKey().PublicKey().Address()

	signableData := &SignableData{
		RequestorId:     "requestor-id",
		BaseTokenAmount: big.NewInt(1000000000000000000),
		BaseToken:       &BaseToken{Address: addr1, Symbol: "ABC", Decimals: 18},
		QuoteToken:      &QuoteToken{Address: addr2, Symbol: "XYZ", Decimals: 18},
		RFQDurationMs:   1000,
	}

	rfqRequest := NewRFQRequest(from, signableData)

	// Create a sample Transaction
	request := NewTx(rfqRequest)

	signedTx, err := request.Sign(privateKey)
	assert.Nil(t, err)
	assert.NotNil(t, signedTx)

	txJSON, err := signedTx.MarshalJSON()
	assert.Nil(t, err)
	fmt.Printf("TX JSON: %s\n", txJSON)

	// Encode the Transaction using the custom EncodeRLP function
	encodedTx := new(bytes.Buffer)
	err = signedTx.EncodeRLP(encodedTx)
	assert.Nil(t, err)
	assert.NotNil(t, encodedTx)
	fmt.Printf("Encoded TX: %x\n", encodedTx.Bytes())

	// Print the encoded data for debugging

	decoded := &Transaction{}
	// Decode the Transaction using the custom DecodeRLP function
	err = decoded.DecodeRLP(rlp.NewStream(bytes.NewReader(encodedTx.Bytes()), 0))
	if err != nil {
		fmt.Printf("Failed to decode RLP: %v\n", err)
	}

	// Print the decoded request for debugging
	fmt.Printf("Decoded Request: %+v\n", decoded)
	decJSON, err := decoded.MarshalJSON()
	assert.Nil(t, err)
	fmt.Printf("Decoded Request JSON: %s\n", decJSON)

	assert.Equal(t, signedTx.From(), decoded.From())

	// Perform assertions to ensure the encoding and decoding worked correctly
	assert.Equal(t, from.Hex(), decoded.From().Hex())
	// assert.Equal(t, rfqRequest.Data.RequestorID, decoded.Data.(*types.RFQRequestTx).RFQRequest.Data.RequestorID)
	// assert.Equal(t, rfqRequest.Data.BaseTokenAmount, decoded.Data().(*types.RFQRequestTx).RFQRequest.Data.BaseTokenAmount)
	// assert.Equal(t, rfqRequest.Data.BaseToken.Address.Hex(), decoded.Data().(*types.RFQRequestTx).RFQRequest.Data.BaseToken.Address.Hex())
	// assert.Equal(t, rfqRequest.Data.BaseToken.Symbol, decoded.Data().(*types.RFQRequestTx).RFQRequest.Data.BaseToken.Symbol)
	// assert.Equal(t, rfqRequest.Data.BaseToken.Decimals, decoded.Data().(*types.RFQRequestTx).RFQRequest.Data.BaseToken.Decimals)
	// assert.Equal(t, rfqRequest.Data.QuoteToken.Address.Hex(), decoded.Data().(*types.RFQRequestTx).RFQRequest.Data.QuoteToken.Address.Hex())
	// assert.Equal(t, rfqRequest.Data.QuoteToken.Symbol, decoded.Data().(*types.RFQRequestTx).RFQRequest.Data.QuoteToken.Symbol)
	// assert.Equal(t, rfqRequest.Data.QuoteToken.Decimals, decoded.Data().(*types.RFQRequestTx).RFQRequest.Data.QuoteToken.Decimals)
	// assert.Equal(t, rfqRequest.Data.RFQDurationMs, decoded.Data().(*types.RFQRequestTx).RFQRequest.Data.RFQDurationMs)
	// assert.Equal(t, signedTx.V(), decoded.V)
	// assert.Equal(t, signedTx.R, decoded.R)
	// assert.Equal(t, signedTx.S, decoded.S)
}

func TestTransactionEncodeDecode(t *testing.T) {
	// create a transaction

	var (
		privateKey = cryptoocax.GeneratePrivateKey()
		pubKey     = privateKey.PublicKey()
		from       = pubKey.Address()
	)

	rfqReq := &SignableData{
		RequestorId:     "abcd1234",
		BaseTokenAmount: big.NewInt(999999990000),
		BaseToken:       &BaseToken{Address: common.HexToAddress("0x9876543210"), Symbol: "ABC", Decimals: 18},
		QuoteToken:      &QuoteToken{Address: common.HexToAddress("0x2468135790"), Symbol: "XYZ", Decimals: 18},
		RFQDurationMs:   uint64(11111),
	}

	rfq := NewRFQRequest(from, rfqReq)
	tx := NewTx(rfq)
	signedTx, err := tx.Sign(privateKey)
	assert.Nil(t, err)

	txJson, err := signedTx.MarshalJSON()
	assert.NoError(t, err, "failed to encode RFQRequest")
	fmt.Printf("Encoded Data: %v\n", string(txJson))
	assert.NoError(t, err, "failed to encode RFQRequest")
	encodedData, err := rlp.EncodeToBytes(signedTx)
	assert.NoError(t, err, "failed to encode RFQRequest")
	t.Logf("Encoded Data: %v", encodedData)

	// Decode RFQRequest
	var decodedTx Transaction

	err = decodedTx.DecodeRLP(rlp.NewStream(bytes.NewReader(encodedData), 0))
	assert.NoError(t, err, "failed to decode RFQRequest")
	t.Logf("Decoded Request: %+v", decodedTx)

	// Encode Transaction

	// encodedTx, err := rlp.EncodeToBytes(tx)
	// assert.NoError(t, err, "failed to encode Transaction")
	// t.Logf("Encoded Transaction: %x", encodedTx)

	// // Decode Transaction
	// decodedTx := Transaction{}
	// err = rlp.DecodeBytes(encodedTx, &decodedTx)
	// assert.NoError(t, err, "failed to decode Transaction")
	// t.Logf("Decoded Transaction: %+v", decodedTx)

	// // Decode Transaction into RFQRequest
	// decodedRequestFromTx := RFQRequest{}
	// err = rlp.DecodeBytes(decodedTx.Data(), &decodedRequestFromTx)
	// assert.NoError(t, err, "failed to decode RFQRequest from Transaction")
	// t.Logf("Decoded Request from Transaction: %+v", decodedRequestFromTx)

	// assert.Equal(t, request, decodedRequestFromTx, "decoded RFQRequest does not match original")
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

func TestBaseTokenRLP(t *testing.T) {
	// 1. Create a sample BaseToken
	baseToken := BaseToken{
		Address:  common.Address{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		Symbol:   "BTC",
		Decimals: 18,
	}

	// 2. Encode it into RLP
	bytes, err := rlp.EncodeToBytes(&baseToken)
	if err != nil {
		t.Errorf("Failed to RLP encode BaseToken: %v", err)
	}

	// 3. Decode it back from RLP
	var decoded BaseToken
	err = rlp.DecodeBytes(bytes, &decoded)
	if err != nil {
		t.Errorf("Failed to RLP decode BaseToken: %v", err)
	}

	// 4. Check if decoded BaseToken matches original one
	if baseToken.Address != decoded.Address || baseToken.Symbol != decoded.Symbol || baseToken.Decimals != decoded.Decimals {
		t.Errorf("Decoded BaseToken doesn't match the original one")
	}
}

func TestSignableData_MarshalUnmarshalJSON(t *testing.T) {
	addr1 := common.HexToAddress("0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2")
	addr2 := common.HexToAddress("0x7EA2be2df7BA6E54B1A9C70676f668455E329d29")
	baseTokenAmount := new(big.Int)
	_, ok := baseTokenAmount.SetString("980000000000000000000000", 10)
	if !ok {
		log.Fatal("Failed to set big.Int value")
	}

	original := &SignableData{
		RequestorId:     "RequestorId",
		BaseTokenAmount: baseTokenAmount,
		BaseToken: &BaseToken{
			Address:  addr1,
			Symbol:   "MKR",
			Decimals: 18,
		},
		QuoteToken: &BaseToken{
			Address:  addr2,
			Symbol:   "USDC",
			Decimals: 18,
		},
		RFQDurationMs: 60000,
	}

	// marshal to JSON
	marshaled, err := original.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// unmarshal back to struct
	unmarshaled := &SignableData{}
	err = unmarshaled.UnmarshalJSON(marshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	fmt.Printf("Original: %+v\n", original)
	fmt.Printf("Unmarshaled: %+v\n", unmarshaled)
	// compare original and unmarshaled structs
	// compare original and unmarshaled structs
	if original.RequestorId != unmarshaled.RequestorId {
		t.Fatalf("RequestorId does not match: original = %v, unmarshaled = %v", original.RequestorId, unmarshaled.RequestorId)
	}
	if original.BaseTokenAmount.Cmp(unmarshaled.BaseTokenAmount) != 0 {
		t.Fatalf("BaseTokenAmount does not match: original = %v, unmarshaled = %v", original.BaseTokenAmount, unmarshaled.BaseTokenAmount)
	}

	if original.BaseToken.Address != unmarshaled.BaseToken.Address {
		t.Fatalf("BaseToken.Address does not match: original = %v, unmarshaled = %v", original.BaseToken.Address, unmarshaled.BaseToken.Address)
	}
	if original.BaseToken.Symbol != unmarshaled.BaseToken.Symbol {
		t.Fatalf("BaseToken.Symbol does not match: original = %v, unmarshaled = %v", original.BaseToken.Symbol, unmarshaled.BaseToken.Symbol)
	}
	if original.BaseToken.Decimals != unmarshaled.BaseToken.Decimals {
		t.Fatalf("BaseToken.Decimals does not match: original = %v, unmarshaled = %v", original.BaseToken.Decimals, unmarshaled.BaseToken.Decimals)
	}
	if original.QuoteToken.Address != unmarshaled.QuoteToken.Address {
		t.Fatalf("QuoteToken.Address does not match: original = %v, unmarshaled = %v", original.QuoteToken.Address, unmarshaled.QuoteToken.Address)
	}
	if original.QuoteToken.Symbol != unmarshaled.QuoteToken.Symbol {
		t.Fatalf("QuoteToken.Symbol does not match: original = %v, unmarshaled = %v", original.QuoteToken.Symbol, unmarshaled.QuoteToken.Symbol)
	}
	if original.QuoteToken.Decimals != unmarshaled.QuoteToken.Decimals {
		t.Fatalf("QuoteToken.Decimals does not match: original = %v, unmarshaled = %v", original.QuoteToken.Decimals, unmarshaled.QuoteToken.Decimals)
	}
	if original.RFQDurationMs != unmarshaled.RFQDurationMs {
		t.Fatalf("RFQDurationMs does not match: original = %v, unmarshaled = %v", original.RFQDurationMs, unmarshaled.RFQDurationMs)
	}

}

func TestTransaction_MarshalUnmarshalJSON(t *testing.T) {
	// create a transaction

	var (
		privateKey = cryptoocax.GeneratePrivateKey()
		pubKey     = privateKey.PublicKey()
		from       = pubKey.Address()
	)

	newRFQ := NewRFQRequest(from, randomRFQ(t))
	originalTx := NewTx(newRFQ)
	original, err := originalTx.Sign(privateKey)
	if err != nil {
		t.Fatalf("could not sign transaction: %v", err)
	}

	// Marshal to JSON
	marshalled, err := original.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal back to Transaction
	unmarshalled := &Transaction{}
	err = unmarshalled.UnmarshalJSON(marshalled)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Ensure the input field can unmarshal to a SignableData struct
	// Compare the original and unmarshalled transactions.
	// This comparison will depend on the specific fields in your Transaction struct.
	// Add more comparisons for all the relevant fields in your transaction.
	assert.Equal(t, original.Type(), unmarshalled.Type())
	assert.Equal(t, original.From(), unmarshalled.From())

	// Compare the data field
	if !reflect.DeepEqual(original.Data(), unmarshalled.Data()) {
		t.Fatalf("Original and unmarshalled transactions: Data does not match")
	}
	// Compare V, R, S
	ov, or, os := original.RawSignatureValues()
	uv, ur, us := unmarshalled.RawSignatureValues()
	assert.Equal(t, ov.Cmp(uv) == 0, true)
	assert.Equal(t, or.Cmp(ur) == 0, true)
	assert.Equal(t, os.Cmp(us) == 0, true)

	rfqRequest := unmarshalled.EmbeddedData().(*SignableData)
	assert.Equal(t, rfqRequest.BaseTokenAmount.Cmp(big.NewInt(0)), 1)
	assert.Equal(t, rfqRequest.BaseToken.Decimals, uint64(18))
	assert.Equal(t, rfqRequest.QuoteToken.Decimals, uint64(6))
	assert.NotNil(t, rfqRequest.BaseToken.Address)
	assert.NotNil(t, rfqRequest.QuoteToken.Address)
	assert.Equal(t, rfqRequest.BaseToken.Symbol, "VFG")
	assert.Equal(t, rfqRequest.QuoteToken.Symbol, "USDC")
}

func randomTxWithSignature(t *testing.T, key cryptoocax.PrivateKey) *Transaction {
	pubKey := key.PublicKey()
	from := pubKey.Address()
	inner := &RFQRequest{
		From: from,
		Data: randomRFQ(t),
	}

	tx := NewTx(inner)

	signedTx, err := tx.Sign(key)
	assert.Nil(t, err)

	return signedTx
}

func TestTokenRLPEncodingDecoding(t *testing.T) {
	token := &Token{
		Address:  common.HexToAddress("0x1234567890ABCDEF1234567890ABCDEF123456789"),
		Symbol:   "XYZ",
		Decimals: 18,
	}

	bytes, err := rlp.EncodeToBytes(token)
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	decodedToken := new(Token)
	err = rlp.DecodeBytes(bytes, decodedToken)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if decodedToken.Address != token.Address {
		t.Errorf("expected %v, got %v", token.Address, decodedToken.Address)
	}

	if decodedToken.Symbol != token.Symbol {
		t.Errorf("expected %v, got %v", token.Symbol, decodedToken.Symbol)
	}

	if decodedToken.Decimals != token.Decimals {
		t.Errorf("expected %v, got %v", token.Decimals, decodedToken.Decimals)
	}
}

func TestQuoteRLPEncodingDecoding(t *testing.T) {
	privateKey := cryptoocax.GeneratePrivateKey()
	publicKey := privateKey.PublicKey()
	from := publicKey.Address()

	baseToken := &BaseToken{
		Address:  common.HexToAddress("0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2"),
		Symbol:   "ABC",
		Decimals: 18,
	}

	quoteToken := &QuoteToken{
		Address:  common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
		Symbol:   "XYZ",
		Decimals: 18,
	}

	quote := NewQuote(
		from,
		&QuoteData{
			QuoterId:             "1234",
			RFQTxHash:            common.HexToHash("0x1234567890"),
			QuoteExpiryTime:      1609459200,
			BaseToken:            baseToken,  // Populate with actual data
			QuoteToken:           quoteToken, // Populate with actual data
			BaseTokenAmount:      big.NewInt(10000),
			BidPrice:             big.NewInt(200),
			AskPrice:             big.NewInt(300),
			EncryptionPublicKeys: []*cryptoocax.PublicKey{}, // Populate with actual data
		},
	)

	fmt.Printf("From: %s\n", hex.EncodeToString(quote.From[:]))
	fmt.Printf("Data: %+v\n", quote.Data)
	fmt.Printf("V: %s\n", quote.V.String())
	fmt.Printf("R: %s\n", quote.R.String())
	fmt.Printf("S: %s\n", quote.S.String())
	encodedData, err := rlp.EncodeToBytes(quote)
	assert.Nil(t, err)
	fmt.Printf("Encoded data: %s\n", hex.EncodeToString(encodedData))
	tx := NewTx(quote)
	signedTx, err := tx.Sign(privateKey)
	assert.Nil(t, err)

	buf := new(bytes.Buffer)
	if err := signedTx.EncodeRLP(buf); err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	fmt.Printf("Encoded data: %s\n", hex.EncodeToString(encodedData))
	// Reset buffer read pointer
	// buf.Reset()

	decodedTx := &Transaction{} // Create new Transaction for decoding
	if err := decodedTx.DecodeRLP(rlp.NewStream(buf, 0)); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	signedDecodedTx, err := decodedTx.Sign(privateKey)
	assert.Nil(t, err)

	// Comparing the encoded quote data with the decoded one
	if signedDecodedTx.EmbeddedData().(*QuoteData).QuoterId != quote.Data.QuoterId {
		t.Errorf("expected %s, got %s", quote.Data.QuoterId, signedDecodedTx.EmbeddedData().(*QuoteData).QuoterId)
	}
}

func TestQuoteDataRLPEncodingDecoding(t *testing.T) {

	baseToken := &BaseToken{
		Address:  common.HexToAddress("0x1234567890"),
		Symbol:   "ABC",
		Decimals: 18,
	}

	quoteToken := &QuoteToken{
		Address:  common.HexToAddress("0x1234567890"),
		Symbol:   "XYZ",
		Decimals: 18,
	}

	quoteData := &QuoteData{
		QuoterId:             "1234",
		RFQTxHash:            common.Hash{},
		QuoteExpiryTime:      1609459200,
		BaseToken:            baseToken,
		QuoteToken:           quoteToken,
		BaseTokenAmount:      big.NewInt(100),
		BidPrice:             big.NewInt(200),
		AskPrice:             big.NewInt(300),
		EncryptionPublicKeys: []*cryptoocax.PublicKey{},
	}

	buf := new(bytes.Buffer)
	if err := quoteData.EncodeRLP(buf); err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	quoteDataDecoded := new(QuoteData)
	if err := quoteDataDecoded.DecodeRLP(rlp.NewStream(buf, 0)); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	// Add more asserts as per the requirement
	if quoteDataDecoded.QuoterId != quoteData.QuoterId {
		t.Errorf("expected %s, got %s", quoteData.QuoterId, quoteDataDecoded.QuoterId)
	}
}
