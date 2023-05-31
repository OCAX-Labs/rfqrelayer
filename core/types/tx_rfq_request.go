package types

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/ethereum/go-ethereum/rlp"
)

type BaseToken struct {
	Address  common.Address `json:"address"`
	Symbol   string         `json:"symbol"`
	Decimals int            `json:"decimals"`
}

func (b BaseToken) String() string {
	return fmt.Sprintf("BaseToken{Address: %s, Symbol: %s, Decimals: %d}",
		b.Address.Hex(),
		b.Symbol,
		b.Decimals)
}

type QuoteToken struct {
	Address  common.Address `json:"address"`
	Symbol   string         `json:"symbol"`
	Decimals int            `json:"decimals"`
}

func (q QuoteToken) String() string {
	return fmt.Sprintf("QuoteToken{Address: %s, Symbol: %s, Decimals: %d}",
		q.Address.Hex(),
		q.Symbol,
		q.Decimals)
}

type SignableRFQData struct {
	RequestorId     string     `json:"requestorId"`
	BaseTokenAmount string     `json:"baseTokenAmount"`
	BaseToken       BaseToken  `json:"baseToken"`
	QuoteToken      QuoteToken `json:"quoteToken"`
	RFQDurationMs   int64      `json:"rfqDurationMs"`
}

func (d SignableRFQData) String() string {
	return fmt.Sprintf("SignableRFQData{RequestorId: %s, BaseTokenAmount: %s, BaseToken: %s, QuoteToken: %s, RFQDurationMs: %d}",
		d.RequestorId,
		d.BaseTokenAmount,
		d.BaseToken.String(),
		d.QuoteToken.String(),
		d.RFQDurationMs)
}

type RFQRequest struct {
	From common.Address  `json:"from" gencodec:"required"`
	Data SignableRFQData `json:"data" gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}

func NewTransaction(from common.Address, data SignableRFQData) *RFQRequest {

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
	dataFields, err := DeepCopy(tx.Data)
	if err != nil {
		panic(fmt.Sprintf("failed to deep copy tx data: %v", err))
	}

	cpy.Data = dataFields

	return cpy
}

func (tx *RFQRequest) from() *common.Address { return &tx.From }
func (tx *RFQRequest) txType() byte          { return RFQRequestTxType }

func (tx *RFQRequest) data() []byte {
	dataBytes, err := json.Marshal(tx.Data)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal tx data: %v", err))
	}
	return dataBytes
}

func (tx *RFQRequest) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}
func (tx *RFQRequest) setSignatureValues(v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}

func (r *RFQRequest) EncodeRLP(w io.Writer) error {
	dataBytes, err := json.Marshal(r.Data)
	if err != nil {
		return err
	}
	return rlp.Encode(w, []interface{}{r.From.Bytes(), dataBytes, r.V, r.R, r.S})
}

func (r *RFQRequest) DecodeRLP(s *rlp.Stream) error {
	var elems []interface{}

	err := s.Decode(&elems)
	if err != nil {
		return err
	}

	if len(elems) != 5 {
		return fmt.Errorf("expected 5 elements, got %d", len(elems))
	}

	if fromBytes, ok := elems[0].([]byte); ok {
		if len(fromBytes) != len(r.From) {
			return errors.New("wrong length for From")
		}
		copy(r.From[:], fromBytes)
	} else {
		return errors.New("invalid type for From")
	}

	var data SignableRFQData
	dataBytes, _ := elems[1].([]byte)
	err = json.Unmarshal(dataBytes, &data)
	if err != nil {
		return err
	}

	r.Data = data
	r.V, _ = elems[2].(*big.Int)
	r.R, _ = elems[3].(*big.Int)
	r.S, _ = elems[4].(*big.Int)

	return nil
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

func DeepCopy(src SignableRFQData) (SignableRFQData, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	dec := gob.NewDecoder(buf)

	err := enc.Encode(src)
	if err != nil {
		return SignableRFQData{}, err
	}

	var copy SignableRFQData
	if err := dec.Decode(&copy); err != nil {
		return SignableRFQData{}, err
	}

	return copy, nil
}

func init() {
	gob.Register(SignableRFQData{})
}
