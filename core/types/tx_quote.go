package types

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/ethereum/go-ethereum/rlp"
)

type QuoteData struct {
	quoterId             string
	RFQRequest           *SignableData
	RFQRequestHash       common.Hash
	quoteExpiryTime      int64
	BidQuoteData         *BidQuoteData
	AskQuoteData         *AskQuoteData
	EncryptionPublicKeys []*cryptoocax.PublicKey
}

type Quote struct {
	From common.Address
	Data *QuoteData
	V    *big.Int `json:"v"`
	R    *big.Int `json:"r"`
	S    *big.Int `json:"s"`
}

func NewQuote(from common.Address, data *QuoteData) *Quote {
	return &Quote{
		From: from,
		Data: data,
	}
}

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

	cpy.Data = &dataFields

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

func (tx *Quote) rfqData() *SignableData {
	return tx.Data.RFQRequest
}

func (tx *Quote) referenceTxHash() common.Hash {
	if tx.Data.RFQRequest == nil {
		return common.Hash{} // return empty hash if there is no reference tx hash
	}
	return tx.Data.RFQRequestHash
}

func (tx *QuoteData) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, tx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (q *QuoteData) deepCopy() (QuoteData, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	dec := gob.NewDecoder(buf)

	err := enc.Encode(q)
	if err != nil {
		return QuoteData{}, err
	}

	var copy QuoteData
	if err := dec.Decode(&copy); err != nil {
		return QuoteData{}, err
	}

	return copy, nil
}

func init() {
	gob.Register(QuoteData{})
}

// func copyPubKey(pubKey *ecdsa.PublicKey) *ecdsa.PublicKey {
// 	if pubKey == nil {
// 		return nil
// 	}
// 	cpy := *pubKey
// 	return &cpy
// }
