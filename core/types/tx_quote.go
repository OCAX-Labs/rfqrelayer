package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/ethereum/go-ethereum/rlp"
)

type QuoteData struct {
	QuoterId             string                  `json:"quoterId"`
	RFQTxHash            common.Hash             `json:"rfqTxHash"`
	QuoteExpiryTime      uint64                  `json:"quoteExpiryTime"`
	BaseToken            *Token                  `json:"baseToken"`
	QuoteToken           *Token                  `json:"quoteToken"`
	BaseTokenAmount      *big.Int                `json:"baseTokenAmount"`
	BidPrice             *big.Int                `json:"bidPrice"`
	AskPrice             *big.Int                `json:"askPrice"`
	EncryptionPublicKeys []*cryptoocax.PublicKey `json:"encryptionPublicKeys"`
}

type Quote struct {
	From common.Address
	Data *QuoteData
	V    *big.Int `json:"v"`
	R    *big.Int `json:"r"`
	S    *big.Int `json:"s"`
}

type Quotes []*Quote

func NewQuote(from common.Address, data *QuoteData) *Quote {
	return &Quote{
		From: from,
		Data: data,
	}
}

func (tx *Quote) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		From common.Address `json:"from"`
		Data *QuoteData     `json:"data"`
		V    *big.Int       `json:"v"`
		R    *big.Int       `json:"r"`
		S    *big.Int       `json:"s"`
	}{
		From: tx.From,
		Data: tx.Data,
		V:    tx.V,
		R:    tx.R,
		S:    tx.S,
	})
}

func (tx *Quote) UnmarshalJSON(data []byte) error {
	type QuoteJSON struct {
		From common.Address  `json:"from"`
		Data json.RawMessage `json:"data"`
		V    *big.Int        `json:"v"`
		R    *big.Int        `json:"r"`
		S    *big.Int        `json:"s"`
	}

	_, err := hex.DecodeString(strings.TrimPrefix(string(data), "0x"))
	if err != nil {
		log.Fatal(err)
	}

	var quoteJSON QuoteJSON
	if err := json.Unmarshal(data, &quoteJSON); err != nil {
		return err
	}

	quoteData := &QuoteData{}
	if err := json.Unmarshal(quoteJSON.Data, quoteData); err != nil {
		return err
	}
	tx.From = quoteJSON.From
	tx.Data = quoteData
	tx.V = quoteJSON.V
	tx.R = quoteJSON.R
	tx.S = quoteJSON.S

	return nil
}

func (q *Quote) EncodeRLP(w io.Writer) error {
	if q.Data == nil {
		return errors.New("Data field is nil")
	}
	return rlp.Encode(w, []interface{}{q.From, q.Data, q.V, q.R, q.S})
}

func (q *Quote) DecodeRLP(st *rlp.Stream) error {

	_, err := st.List()
	if err != nil {
		return err
	}

	var from common.Address
	if err := st.Decode(&from); err != nil {
		return err
	}
	q.From = from

	var data QuoteData
	if err := st.Decode(&data); err != nil {
		return err
	}

	q.Data = &data

	var v, r, s *big.Int

	if err := st.Decode(&v); err != nil {
		return err
	}
	q.V = v
	if err := st.Decode(&r); err != nil {
		return err
	}
	q.R = r
	if err := st.Decode(&s); err != nil {
		return err
	}
	q.S = s

	return st.ListEnd()
}

func (q *Quote) FromInterfaces(data []interface{}) error {
	if len(data) != 5 {
		return fmt.Errorf("wrong number of elements: expected 5, got %d", len(data))
	}

	fromBytes, ok := data[0].([]byte)
	if !ok {
		return fmt.Errorf("invalid from type %T", data[0])
	}
	if len(fromBytes) != common.AddressLength {
		return fmt.Errorf("incorrect length for from, expected %d, got %d", common.AddressLength, len(fromBytes))
	}
	q.From = common.BytesToAddress(fromBytes)

	qd := new(QuoteData)
	if err := qd.FromInterfaces(data[1].([]interface{})); err != nil {
		return err
	}
	q.Data = qd

	vBytes, ok := data[2].([]byte)
	if !ok {
		return fmt.Errorf("invalid v type %T", data[2])
	}
	if len(vBytes) != 1 {
		return fmt.Errorf("incorrect length for v, expected %d, got %d", 1, len(vBytes))
	}
	q.V = new(big.Int).SetBytes(vBytes)

	rBytes, ok := data[3].([]byte)
	if !ok {
		return fmt.Errorf("invalid r type %T", data[3])
	}
	if len(rBytes) != common.HashLength {
		return fmt.Errorf("incorrect length for r, expected %d, got %d", common.HashLength, len(rBytes))
	}
	q.R = new(big.Int).SetBytes(rBytes)

	sBytes, ok := data[4].([]byte)
	if !ok {
		return fmt.Errorf("invalid s type %T", data[4])
	}
	if len(sBytes) != common.HashLength {
		return fmt.Errorf("incorrect length for s, expected %d, got %d", common.HashLength, len(sBytes))
	}
	q.S = new(big.Int).SetBytes(sBytes)

	return nil
}

func (qd *QuoteData) FromInterfaces(data []interface{}) error {
	if len(data) != 8 {
		return fmt.Errorf("wrong number of elements: expected 8, got %d", len(data))
	}

	quoterIdBytes, ok := data[0].([]byte)
	if !ok {
		return fmt.Errorf("invalid requestorId type %T", data[0])
	}

	quoterId := string(quoterIdBytes)

	rfqTxHashBytes, ok := data[1].([]byte)
	if !ok {
		return errors.New("data[0] is not a byte array")
	}

	if len(rfqTxHashBytes) != common.HashLength {
		return fmt.Errorf("incorrect length for rfqTxHash, expected %d, got %d", common.HashLength, len(rfqTxHashBytes))
	}

	var rfqTxHash common.Hash
	copy(rfqTxHash[:], rfqTxHashBytes)

	// Handle RFQDurationMs as []byte
	quoteExpiryTimeBytes, ok := data[2].([]byte)
	if !ok {
		return fmt.Errorf("invalid quoteExpiryTime type %T", data[2])
	}
	if len(quoteExpiryTimeBytes) > 8 {
		return errors.New("invalid quoteExpiryTime length")
	}

	// Create a new byte slice of length 8
	newQuoteExpiryTimeBytes := make([]byte, 8)

	// Copy rfqDurationBytes to the end of newRfqDurationBytes
	copy(newQuoteExpiryTimeBytes[8-len(quoteExpiryTimeBytes):], quoteExpiryTimeBytes)

	// Convert the bytes to uint64
	quoteExpiryTime := binary.BigEndian.Uint64(newQuoteExpiryTimeBytes)

	baseTokenData, ok := data[3].([]interface{})
	if !ok {
		return fmt.Errorf("invalid baseToken type %T", data[3])
	}
	baseToken := new(Token)
	if err := baseToken.FromInterfaces(baseTokenData); err != nil {
		return err
	}

	quoteTokenData, ok := data[4].([]interface{})
	if !ok {
		return fmt.Errorf("invalid quoteToken type %T", data[4])
	}
	quoteToken := new(Token)
	if err := quoteToken.FromInterfaces(quoteTokenData); err != nil {
		return err
	}

	baseTokenAmountBytes, ok := data[5].([]byte)
	if !ok {
		return fmt.Errorf("invalid baseTokenAmount type %T", data[5])
	}
	baseTokenAmount := new(big.Int).SetBytes(baseTokenAmountBytes)

	bidPriceBytes, ok := data[6].([]byte)
	if !ok {
		return fmt.Errorf("invalid bidPrice type %T", data[6])
	}
	bidPrice := new(big.Int).SetBytes(bidPriceBytes)

	askPriceBytes, ok := data[7].([]byte)
	if !ok {
		return fmt.Errorf("invalid askPrice type %T", data[7])
	}
	askPrice := new(big.Int).SetBytes(askPriceBytes)

	encryptionPublicKeysInterface, ok := data[8].([]interface{})
	if !ok {
		return fmt.Errorf("invalid encryptionPublicKeys type %T", data[8])
	}

	var encryptionPublicKeys []*cryptoocax.PublicKey
	for _, encryptionPublicKeyInterface := range encryptionPublicKeysInterface {
		encryptionPublicKeyBytes, ok := encryptionPublicKeyInterface.([]byte)
		if !ok {
			return fmt.Errorf("invalid encryptionPublicKey type %T", encryptionPublicKeyInterface)
		}

		encryptionPublicKey, err := cryptoocax.BytesToPublicKey(encryptionPublicKeyBytes)
		if err != nil {
			return err
		}

		encryptionPublicKeys = append(encryptionPublicKeys, &encryptionPublicKey)
	}

	qd.QuoterId = quoterId
	qd.RFQTxHash = rfqTxHash
	qd.QuoteExpiryTime = quoteExpiryTime
	qd.BaseToken = baseToken
	qd.QuoteToken = quoteToken
	qd.BaseTokenAmount = baseTokenAmount
	qd.BidPrice = bidPrice
	qd.AskPrice = askPrice
	qd.EncryptionPublicKeys = encryptionPublicKeys

	return nil
}

func (q *Quote) DataString() string {
	dataBytes, err := json.Marshal(q.Data)
	if err != nil {
		return "error marshalling quote data"
	}
	return string(dataBytes)
}

func (q *Quote) String() string {
	return fmt.Sprintf("Quote{From: %s, Data: %s, V: %s, R: %s, S: %s}",
		q.From.Hex(),
		q.DataString(),
		q.V.String(),
		q.R.String(),
		q.S.String(),
	)
}

// func (q *Quote) Hash() common.Hash {
// 	return common.BytesToHash(q.From.Bytes())
// }

// type quoteRLP struct {
// 	From       *common.Address
// 	Signature  *cryptoocax.Signature
// 	Data       []byte
// 	RFQRequest *common.Hash
// }

// func (tx *Quote) EncodeRLP(w io.Writer) error {
// 	return rlp.Encode(w, &quoteRLP{
// 		From:       tx.From,
// 		Signature:  tx.Signature,
// 		Data:       tx.Data,
// 		RFQRequest: tx.RFQRequest,
// 	})
// }

// func (tx *Quote) DecodeRLP(s *rlp.Stream) error {
// 	var dec quoteRLP
// 	if err := s.Decode(&dec); err != nil {
// 		return err
// 	}

// 	tx.From = dec.From
// 	tx.Signature = dec.Signature
// 	tx.Data = dec.Data
// 	tx.RFQRequest = dec.RFQRequest
// 	return nil
// }

func (tx *Quote) copy() TxData {
	cpy := &Quote{
		From: common.Address(common.CopyBytes(tx.From.Bytes())),

		// These are initialized below.
		// These are initialized below.
		V: new(big.Int),
		R: new(big.Int),
		S: new(big.Int),
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}

	// Deep copy the data.
	dataFields, err := tx.Data.deepCopy()
	if err != nil {
		panic(fmt.Sprintf("failed to deep copy tx data: %v", err))
	}

	cpy.Data = dataFields

	return cpy
}

func (tx *Quote) from() *common.Address { return &tx.From }
func (tx *Quote) txType() byte          { return QuoteTxType }
func (tx *Quote) data() []byte {
	txDataBytes, err := tx.Data.ToBytes()
	if err != nil {
		panic(fmt.Sprintf("failed to encode tx data: %v", err))
	}
	return txDataBytes
}

func (tx *Quote) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *Quote) setSignatureValues(v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}

func (tx *Quote) quoteData() *QuoteData {
	return tx.Data
}

func (tx *Quote) embeddedData() interface{} {
	return tx.quoteData()
}

func (tx *Quote) referenceTxHash() common.Hash {
	return tx.Data.RFQTxHash
}

func (qd *QuoteData) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{
		qd.QuoterId,
		qd.RFQTxHash,
		qd.QuoteExpiryTime,
		qd.BaseToken,
		qd.QuoteToken,
		qd.BaseTokenAmount,
		qd.BidPrice,
		qd.AskPrice,
		qd.EncryptionPublicKeys,
	})
}

func (qd *QuoteData) DecodeRLP(s *rlp.Stream) error {
	var dataToDecode struct {
		QuoterId             string
		RFQTxHash            common.Hash
		QuoteExpiryTime      uint64
		BaseToken            *Token
		QuoteToken           *Token
		BaseTokenAmount      *big.Int
		BidPrice             *big.Int
		AskPrice             *big.Int
		EncryptionPublicKeys []*cryptoocax.PublicKey
	}
	if err := s.Decode(&dataToDecode); err != nil {
		return err
	}

	qd.QuoterId = dataToDecode.QuoterId
	qd.RFQTxHash = dataToDecode.RFQTxHash
	qd.QuoteExpiryTime = dataToDecode.QuoteExpiryTime
	qd.BaseToken = dataToDecode.BaseToken
	qd.QuoteToken = dataToDecode.QuoteToken
	qd.BaseTokenAmount = dataToDecode.BaseTokenAmount
	qd.BidPrice = dataToDecode.BidPrice
	qd.AskPrice = dataToDecode.AskPrice
	qd.EncryptionPublicKeys = dataToDecode.EncryptionPublicKeys
	return nil
}

func (tx *QuoteData) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, tx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (q *QuoteData) Validate() error {
	return nil
}

func (q *QuoteData) deepCopy() (*QuoteData, error) {
	cpy := &QuoteData{
		QuoterId:             string(q.QuoterId),
		RFQTxHash:            q.RFQTxHash,
		QuoteExpiryTime:      q.QuoteExpiryTime,
		BaseToken:            q.BaseToken,
		QuoteToken:           q.QuoteToken,
		BaseTokenAmount:      q.BaseTokenAmount,
		BidPrice:             q.BidPrice,
		AskPrice:             q.AskPrice,
		EncryptionPublicKeys: []*cryptoocax.PublicKey{},
	}
	cpy.EncryptionPublicKeys = make([]*cryptoocax.PublicKey, len(q.EncryptionPublicKeys))
	copy(cpy.EncryptionPublicKeys, q.EncryptionPublicKeys)

	return cpy, nil
}
