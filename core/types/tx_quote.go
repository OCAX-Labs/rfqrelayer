package types

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
)

type Quote struct {
	From      *common.Address
	Signature *cryptoocax.Signature
	Data      []byte
}

func NewQuote(from *common.Address, data []byte) *Quote {
	return &Quote{
		From: from,
		Data: data,
	}
}

func (tx *Quote) copy() TxData {
	cpy := &Quote{
		From: tx.From,

		Data: common.CopyBytes(tx.Data),
		// These are initialized below.
		Signature: &cryptoocax.Signature{
			V: new(big.Int),
			R: new(big.Int),
			S: new(big.Int),
		},
	}
	if tx.Signature.V != nil {
		cpy.Signature.V.Set(tx.Signature.V)
	}
	if tx.Signature.R != nil {
		cpy.Signature.R.Set(tx.Signature.R)
	}
	if tx.Signature.S != nil {
		cpy.Signature.S.Set(tx.Signature.S)
	}
	return cpy
}

func (tx *Quote) from() *common.Address { return tx.From }
func (tx *Quote) txType() byte          { return QuoteTxType }
func (tx *Quote) data() []byte          { return tx.Data }

func (tx *Quote) rawSignatureValues() (v, r, s *big.Int) {
	return tx.Signature.V, tx.Signature.R, tx.Signature.S
}
func (tx *Quote) setSignatureValues(v, r, s *big.Int) {
	tx.Signature.V, tx.Signature.R, tx.Signature.S = v, r, s
}

func copyPubKey(pubKey *ecdsa.PublicKey) *ecdsa.PublicKey {
	if pubKey == nil {
		return nil
	}
	cpy := *pubKey
	return &cpy
}
