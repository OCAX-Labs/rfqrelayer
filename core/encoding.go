package core

import (
	"io"

	"github.com/OCAX-labs/rfqrelayer/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// type Encoder[T any] interface {
// 	Encode(T) error
// }

// type Decoder[T any] interface {
// 	Decode(T) error
// }

type RLPTxEncoder struct {
	w io.Writer
}

func NewRLPTxEncoder(w io.Writer) *RLPTxEncoder {
	return &RLPTxEncoder{w: w}
}

func (e *RLPTxEncoder) Encode(tx *types.Transaction) error {
	return rlp.Encode(e.w, tx)
}

type RLPTxDecoder struct {
	r io.Reader
}

func NewRLPTxDecoder(r io.Reader) *RLPTxDecoder {
	return &RLPTxDecoder{r: r}
}

func (d *RLPTxDecoder) Decode(tx *types.Transaction) error {
	return rlp.Decode(d.r, tx)
}

type RLPBlockEncoder struct {
	w io.Writer
}

func NewRLPBlockEncoder(w io.Writer) *RLPBlockEncoder {
	return &RLPBlockEncoder{w: w}
}

func (enc *RLPBlockEncoder) Encode(block *types.Block) error {
	return rlp.Encode(enc.w, block)
}

type RLPBlockDecoder struct {
	r io.Reader
}

func NewRLPBlockDecoder(r io.Reader) *RLPBlockDecoder {
	return &RLPBlockDecoder{r: r}
}

func (dec *RLPBlockDecoder) Decode(block *types.Block) error {
	return rlp.Decode(dec.r, block)
}
