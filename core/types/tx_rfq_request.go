package types

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

type Token struct {
	Address  common.Address `json:"address"`
	Symbol   string         `json:"symbol"`
	Decimals uint64         `json:"decimals"`
}

// // Decode the RLP fields into a temporary struct
func (t Token) String() string {
	return fmt.Sprintf("BaseToken{Address: %s, Symbol: %s, Decimals: %d}",
		t.Address.Hex(),
		t.Symbol,
		t.Decimals)
}

func (t Token) Validate() bool {
	if t.Address == (common.Address{}) {
		return false
	}
	if t.Symbol == "" {
		return false
	}
	if t.Decimals == 0 {
		return false
	}
	return true
}

type QuoteToken = Token

type BaseToken = Token
type SignableData struct {
	RequestorId     string      `json:"requestorId"`
	BaseTokenAmount *big.Int    `json:"baseTokenAmount"`
	BaseToken       *BaseToken  `json:"baseToken"`
	QuoteToken      *QuoteToken `json:"quoteToken"`
	RFQDurationMs   uint64      `json:"rfqDurationMs"`
}

func (d SignableData) String() string {
	return fmt.Sprintf("SignableData{RequestorId: %s, BaseTokenAmount: %s, BaseToken: %s, QuoteToken: %s, RFQDurationMs: %d}",
		d.RequestorId,
		d.BaseTokenAmount,
		d.BaseToken.String(),
		d.QuoteToken.String(),
		d.RFQDurationMs)
}

type RFQRequest struct {
	From common.Address `json:"from"`
	Data *SignableData  `json:"data"`
	V    *big.Int       `json:"v"`
	R    *big.Int       `json:"r"`
	S    *big.Int       `json:"s"`
}

func (t *Token) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Address  string `json:"address"`
		Symbol   string `json:"symbol"`
		Decimals uint64 `json:"decimals"`
	}{
		Address:  t.Address.Hex(),
		Symbol:   t.Symbol,
		Decimals: t.Decimals,
	})
}

func (t *Token) UnmarshalJSON(input []byte) error {
	type TokenJSON struct {
		Address  string `json:"address"`
		Symbol   string `json:"symbol"`
		Decimals uint64 `json:"decimals"`
	}
	var tokenJson TokenJSON
	if err := json.Unmarshal(input, &tokenJson); err != nil {
		return err
	}
	if !strings.HasPrefix(tokenJson.Address, "0x") || len(tokenJson.Address) != 42 {
		return fmt.Errorf("invalid ethereum address: %s", tokenJson.Address)
	}

	t.Address = common.HexToAddress(tokenJson.Address)
	t.Symbol = tokenJson.Symbol
	t.Decimals = tokenJson.Decimals
	return nil
}

func (d *SignableData) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RequestorId     string     `json:"requestorId"`
		BaseTokenAmount *big.Int   `json:"baseTokenAmount"`
		BaseToken       *BaseToken `json:"baseToken"`
		QuoteToken      *BaseToken `json:"quoteToken"`
		RFQDurationMs   uint64     `json:"rfqDurationMs"`
	}{
		RequestorId:     d.RequestorId,
		BaseTokenAmount: d.BaseTokenAmount,
		BaseToken:       d.BaseToken,
		QuoteToken:      d.QuoteToken,
		RFQDurationMs:   d.RFQDurationMs,
	})
}

func (d *SignableData) UnmarshalJSON(input []byte) error {
	type SignableDataJSON struct {
		RequestorId     string     `json:"requestorId"`
		BaseTokenAmount *big.Int   `json:"baseTokenAmount"`
		BaseToken       *BaseToken `json:"baseToken"`
		QuoteToken      *BaseToken `json:"quoteToken"`
		RFQDurationMs   uint64     `json:"rfqDurationMs"`
	}
	var signableDataJSON SignableDataJSON
	if err := json.Unmarshal(input, &signableDataJSON); err != nil {
		return err
	}

	d.RequestorId = signableDataJSON.RequestorId
	d.BaseTokenAmount = signableDataJSON.BaseTokenAmount
	d.BaseToken = signableDataJSON.BaseToken
	d.QuoteToken = signableDataJSON.QuoteToken
	d.RFQDurationMs = signableDataJSON.RFQDurationMs
	return nil
}

func (tx *RFQRequest) MarshalJSON() ([]byte, error) {
	// Encode RFQRequest data
	data, err := tx.Data.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		From string      `json:"from"`
		Data interface{} `json:"data"`
		V    string      `json:"v"`
		R    string      `json:"r"`
		S    string      `json:"s"`
	}{
		From: tx.From.Hex(),
		Data: data,
		V:    tx.V.String(),
		R:    tx.R.String(),
		S:    tx.S.String(),
	})
}
func (r *RFQRequest) UnmarshalJSON(input []byte) error {
	fmt.Println(string(input))
	type RFQRequestJSON struct {
		From common.Address  `json:"from"`
		Data json.RawMessage `json:"data"`
		V    *big.Int        `json:"v"`
		R    *big.Int        `json:"r"`
		S    *big.Int        `json:"s"`
	}

	decoded, err := hex.DecodeString(strings.TrimPrefix(string(input), "0x"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("decoded: %s\n", string(decoded))
	var rfqRequestJSON RFQRequestJSON
	if err := json.Unmarshal(input, &rfqRequestJSON); err != nil {
		return err
	}

	signableData := &SignableData{}
	if err := json.Unmarshal(rfqRequestJSON.Data, signableData); err != nil {
		return err
	}

	r.From = rfqRequestJSON.From
	r.Data = signableData
	r.V = rfqRequestJSON.V
	r.R = rfqRequestJSON.R
	r.S = rfqRequestJSON.S

	return nil
}

func NewRFQRequest(from common.Address, data *SignableData) *RFQRequest {

	return &RFQRequest{
		Data: data,
		From: from,
	}
}

func (tx *RFQRequest) AddSignatureToTx(sig []byte) error {
	if len(sig) != 65 {
		return errors.New("invalid signature length")
	}
	tx.V = new(big.Int).SetBytes(sig[64:])
	tx.R = new(big.Int).SetBytes(sig[:32])
	tx.S = new(big.Int).SetBytes(sig[32:64])
	return nil
}

func (tx *RFQRequest) copy() TxData {
	cpy := &RFQRequest{
		From: common.Address(common.CopyBytes(tx.From.Bytes())),
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

	cpy.Data = &dataFields

	return cpy
}

func (tx *RFQRequest) from() *common.Address { return &tx.From }
func (tx *RFQRequest) txType() byte          { return RFQRequestTxType }

func (tx *RFQRequest) data() []byte {
	txDataBytes, err := tx.Data.ToBytes()
	if err != nil {
		panic(err)
	}

	return txDataBytes
}

func (tx *RFQRequest) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *RFQRequest) setSignatureValues(v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}
func (tx *RFQRequest) referenceTxHash() common.Hash {
	return common.Hash{}
}

func (tx *RFQRequest) DataString() string {
	dataBytes, err := json.MarshalIndent(tx.Data, "", "  ")
	if err != nil {
		// handle error here or return an error string
		return "error in marshaling data"
	}
	return string(dataBytes)
}

func (tx *RFQRequest) String() string {
	return fmt.Sprintf("RFQRequest{From: %s, Data: %s, V: %s, R: %s, S: %s}",
		tx.From.Hex(),
		tx.DataString(),
		tx.V.String(),
		tx.R.String(),
		tx.S.String())
}

// Returns the RFQRequest data as a SignableData Struct
func (tx *RFQRequest) rfqData() *SignableData {
	return tx.Data
}

func (s *SignableData) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *SignableData) ToHex() (hexutil.Bytes, error) {
	bytes, err := s.ToBytes()
	if err != nil {
		return nil, err
	}
	return hexutil.Bytes(bytes), nil
}

func (s *SignableData) Validate() error {
	if s == nil {
		return errors.New("nil signable data")
	}

	// validate the RequestorId is not empty
	if s.RequestorId == "" {
		return errors.New("empty requestor id")
	}

	// validate the baseToken correctly specified
	if s.BaseToken == nil {
		return errors.New("empty base token")
	}

	if !s.BaseToken.Validate() {
		return errors.New("invalid base token")
	}

	if s.QuoteToken == nil {
		return errors.New("empty quote token")
	}

	if !s.QuoteToken.Validate() {
		return errors.New("invalid quote token")
	}

	// Add any additional validations here
	return nil
}

func (src *SignableData) deepCopy() (SignableData, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	dec := gob.NewDecoder(buf)

	err := enc.Encode(src)
	if err != nil {
		return SignableData{}, err
	}

	var copy SignableData
	if err := dec.Decode(&copy); err != nil {
		return SignableData{}, err
	}

	return copy, nil
}

func init() {
	gob.Register(SignableData{})
}

func bytesToUint64(b []byte) uint64 {
	var buf [8]byte
	copy(buf[8-len(b):], b)
	return binary.BigEndian.Uint64(buf[:])
}
