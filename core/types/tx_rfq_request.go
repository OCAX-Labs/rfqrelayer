package types

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/ethereum/go-ethereum/rlp"
)

type RFQRequest struct {
	From common.Address `json:"from" gencodec:"required"`
	Data []byte
	// Signature values

	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}

func NewTransaction(from common.Address, data []byte) *RFQRequest {

	return &RFQRequest{
		Data: data,
		From: from,
	}
}

func (tx *RFQRequest) copy() TxData {
	cpy := &RFQRequest{
		From: common.Address(common.CopyBytes(tx.From.Bytes())),
		Data: common.CopyBytes(tx.Data),
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
	return cpy
}

func (tx *RFQRequest) from() *common.Address { return &tx.From }
func (tx *RFQRequest) txType() byte          { return RFQRequestTxType }
func (tx *RFQRequest) data() []byte          { return tx.Data }
func (tx *RFQRequest) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}
func (tx *RFQRequest) setSignatureValues(v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}

func (r *RFQRequest) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{r.From.Bytes(), r.Data, r.V, r.R, r.S})
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

	r.Data, _ = elems[1].([]byte)
	r.V, _ = elems[2].(*big.Int)
	r.R, _ = elems[3].(*big.Int)
	r.S, _ = elems[4].(*big.Int)

	return nil
}
