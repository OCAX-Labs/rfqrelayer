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

type RFQData struct {
	RFQTxHash          common.Hash    `json:"rfqTxHash"`
	RFQRequest         *SignableData  `json:"rfqRequest"`
	RFQStartTime       int64          `json:"rfqStartTime"` // this will hold a Unix timestamp
	RFQEndTime         int64          `json:"rfqEndTime"`   // this will hold a Unix timestamp
	SettlementContract common.Address `json:"settlementContract"`
	MatchingContract   common.Address `json:"matchingContract"`
}

func (d RFQData) String() string {
	return fmt.Sprintf(
		`RFQData{
    RFQTxHash: %s, 
    RfqRequest: %s, 
    RFQStartTime: %d, 
    RFQEndTime: %d, 
    SettlementContract: %s, 
    MatchingContract: %s}`,
		d.RFQTxHash.Hex(),
		d.RFQRequest.String(),
		d.RFQStartTime,
		d.RFQEndTime,
		d.SettlementContract.Hex(),
		d.MatchingContract.Hex())
}

type OpenRFQ struct {
	From common.Address `json:"from" gencodec:"required"`
	Data *RFQData       `json:"data" gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}

func NewOpenRFQ(from common.Address, data *RFQData) *OpenRFQ {

	return &OpenRFQ{
		Data: data,
		From: from,
	}
}

func (tx *OpenRFQ) AddSignatureToTx(sig []byte) error {
	if len(sig) != 65 {
		return errors.New("invalid signature length")
	}
	tx.V = new(big.Int).SetBytes(sig[64:])
	tx.R = new(big.Int).SetBytes(sig[:32])
	tx.S = new(big.Int).SetBytes(sig[32:64])
	return nil
}

func (tx *OpenRFQ) copy() TxData {
	cpy := &OpenRFQ{
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

	cpy.Data = dataFields

	return cpy
}

func (tx *OpenRFQ) from() *common.Address { return &tx.From }
func (tx *OpenRFQ) txType() byte          { return OpenRFQTxType }

func (tx *OpenRFQ) data() []byte {
	dataBytes, err := json.Marshal(tx.Data)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal tx data: %v", err))
	}
	return dataBytes
}

func (tx *OpenRFQ) rfqData() *SignableData {
	return tx.Data.RFQRequest
}

// the hash of the underlying RFQRquest transaction that led to this OpenRFQ
func (tx *OpenRFQ) referenceTxHash() common.Hash {
	return tx.Data.RFQTxHash
}

func (tx *OpenRFQ) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}
func (tx *OpenRFQ) setSignatureValues(v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}

func (r *OpenRFQ) EncodeRLP(w io.Writer) error {
	dataBytes, err := json.Marshal(r.Data)
	if err != nil {
		return err
	}
	return rlp.Encode(w, []interface{}{r.From.Bytes(), dataBytes, r.V, r.R, r.S})
}

func (r *OpenRFQ) DecodeRLP(s *rlp.Stream) error {
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

	var data RFQData
	dataBytes, _ := elems[1].([]byte)
	err = json.Unmarshal(dataBytes, &data)
	if err != nil {
		return err
	}

	r.Data = &data
	r.V, _ = elems[2].(*big.Int)
	r.R, _ = elems[3].(*big.Int)
	r.S, _ = elems[4].(*big.Int)

	return nil
}

func (tx *OpenRFQ) DataString() string {
	dataBytes, err := json.MarshalIndent(tx.Data, "", "  ")
	if err != nil {
		// handle error here or return an error string
		return "error in marshaling data"
	}
	return string(dataBytes)
}

func (tx *OpenRFQ) String() string {
	return fmt.Sprintf("OpenRFQ{From: %s, Data: %s, V: %s, R: %s, S: %s}",
		tx.From.Hex(),
		tx.DataString(),
		tx.V.String(),
		tx.R.String(),
		tx.S.String())
}

func (src *RFQData) deepCopy() (*RFQData, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	dec := gob.NewDecoder(buf)

	err := enc.Encode(src)
	if err != nil {
		return &RFQData{}, err
	}

	var copy RFQData
	if err := dec.Decode(&copy); err != nil {
		return &RFQData{}, err
	}

	return &copy, nil
}

func init() {
	gob.Register(RFQData{})
}
