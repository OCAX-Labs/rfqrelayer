package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// type HexBigInt struct {
// 	big.Int
// }

// func (i *HexBigInt) MarshalJSON() ([]byte, error) {
// 	if i.Int.Sign() == 0 {
// 		return []byte("\"0x0\""), nil
// 	}
// 	return []byte(fmt.Sprintf("\"0x%x\"", i.Int.Bytes())), nil
// }

// func (i *HexBigInt) UnmarshalJSON(input []byte) error {
// 	str := string(input)
// 	if str == "\"0x0\"" {
// 		i.Int.SetInt64(0)
// 		return nil
// 	}

// 	// Remove quotes and "0x" prefix
// 	str = str[3 : len(str)-1]

// 	// Convert hexadecimal string to big.Int
// 	n, success := new(big.Int).SetString(str, 16)
// 	if !success {
// 		return errors.New("invalid hexadecimal value")
// 	}

// 	i.Int = *n
// 	return nil
// }

// txJSON is the JSON representation of transactions.
type txJSON struct {
	Type  hexutil.Uint64  `json:"type"`
	From  *common.Address `json:"from"`
	Input *hexutil.Bytes  `json:"input"`

	V *hexutil.Big `json:"v"`
	R *hexutil.Big `json:"r"`
	S *hexutil.Big `json:"s"`

	// Only used for encoding:
	Hash common.Hash `json:"hash"`
}

// MarshalJSON marshals as JSON with a hash.
func (tx *Transaction) MarshalJSON() ([]byte, error) {
	var enc txJSON
	// These are set for all tx types.
	enc.Hash = tx.Hash()
	enc.Type = hexutil.Uint64(tx.Type())

	// Other fields are set conditionally depending on tx type.
	switch itx := tx.inner.(type) {
	case *RFQRequest:
		enc.From = tx.From()
		// Serialize the SignableData into bytes.
		dataBytes, err := itx.Data.JSON()
		if err != nil {
			return nil, err
		}
		enc.Input = (*hexutil.Bytes)(&dataBytes)
		enc.V = (*hexutil.Big)(itx.V)
		enc.R = (*hexutil.Big)(itx.R)
		enc.S = (*hexutil.Big)(itx.S)

		// case *OpenRFQ:
		// 	enc.From = tx.From()
		// 	// Serialize the SignableData into bytes.
		// 	dataBytes, err := itx.Data.MarshalJSON()
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// 	enc.Input = (*hexutil.Bytes)(&itx.Data)
		// 	enc.V = (*hexutil.Big)(itx.V)
		// 	enc.R = (*hexutil.Big)(itx.R)
		// 	enc.S = (*hexutil.Big)(itx.S)

		// case *ClosedRFQ:
		// 	enc.From = tx.From()
		// 	enc.Input = (*hexutil.Bytes)(&itx.Data)
		// 	enc.V = (*hexutil.Big)(itx.V)
		// 	enc.R = (*hexutil.Big)(itx.R)
		// 	enc.S = (*hexutil.Big)(itx.S)

		// case *MatchTxType:
		// 	enc.From = tx.From()
		// 	enc.Input = (*hexutil.Bytes)(&itx.Data)
		// 	enc.V = (*hexutil.Big)(itx.V)
		// 	enc.R = (*hexutil.Big)(itx.R)
		// 	enc.S = (*hexutil.Big)(itx.S)

		// case *QuoteTxType:
		// 	enc.From = tx.From()
		// 	enc.Input = (*hexutil.Bytes)(&itx.Data)
		// 	enc.V = (*hexutil.Big)(itx.V)
		// 	enc.R = (*hexutil.Big)(itx.R)
		// 	enc.S = (*hexutil.Big)(itx.S)

		// case *SettledRFQTxType:
		// 	enc.From = tx.From()
		// 	enc.Input = (*hexutil.Bytes)(&itx.Data)
		// 	enc.V = (*hexutil.Big)(itx.V)
		// 	enc.R = (*hexutil.Big)(itx.R)
		// 	enc.S = (*hexutil.Big)(itx.S)
	}
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (tx *Transaction) UnmarshalJSON(input []byte) error {
	fmt.Printf("UnmarshalJSON: %s\n", string(input))
	var dec txJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}

	// Decode / verify fields according to transaction type.
	var inner TxData
	switch dec.Type {
	case RFQRequestTxType:
		var itx RFQRequest
		inner = &itx
		if dec.From != nil {
			itx.From = *dec.From
		}
		if dec.Input == nil {
			return errors.New("missing required field 'input' in transaction")
		}
		// Deserialize the bytes into SignableData.
		itx.Data = &SignableData{}
		if err := itx.Data.UnmarshalJSON(*dec.Input); err != nil {
			return err
		}
		if dec.V == nil {
			return errors.New("missing required field 'v' in transaction")
		}
		itx.V = dec.V.ToInt()
		if dec.R == nil {
			return errors.New("missing required field 'r' in transaction")
		}
		itx.R = dec.R.ToInt()
		if dec.S == nil {
			return errors.New("missing required field 's' in transaction")
		}
		itx.S = dec.S.ToInt()

		withSignature := itx.V.Sign() != 0 || itx.R.Sign() != 0 || itx.S.Sign() != 0
		if withSignature {
			if err := sanityCheckSignature(itx.V, itx.R, itx.S, true); err != nil {
				return err
			}
		}

	// case OpenRFQTxType:
	// 	var itx OpenRFQ
	// 	inner = &itx
	// 	if dec.From != nil {
	// 		itx.From = *dec.From
	// 	}
	// 	if dec.Input == nil {
	// 		return errors.New("missing required field 'input' in transaction")
	// 	}
	// 	itx.Data = *dec.Input
	// 	if dec.V == nil {
	// 		return errors.New("missing required field 'v' in transaction")
	// 	}
	// 	itx.V = (*big.Int)(dec.V)
	// 	if dec.R == nil {
	// 		return errors.New("missing required field 'r' in transaction")
	// 	}
	// 	itx.R = (*big.Int)(dec.R)
	// 	if dec.S == nil {
	// 		return errors.New("missing required field 's' in transaction")
	// 	}
	// 	itx.S = (*big.Int)(dec.S)
	// 	withSignature := itx.V.Sign() != 0 || itx.R.Sign() != 0 || itx.S.Sign() != 0
	// 	if withSignature {
	// 		if err := sanityCheckSignature(itx.V, itx.R, itx.S, false); err != nil {
	// 			return err
	// 		}
	// 	}

	// case *ClosedRFQTxType:
	// 	var itx ClosedRFQ
	// 	inner = &itx
	// 	if dec.From != nil {
	// 		itx.From = dec.From
	// 	}
	// 	if dec.Input == nil {
	// 		return errors.New("missing required field 'input' in transaction")
	// 	}
	// 	itx.Data = *dec.Input
	// 	if dec.V == nil {
	// 		return errors.New("missing required field 'v' in transaction")
	// 	}
	// 	itx.V = (*big.Int)(dec.V)
	// 	if dec.R == nil {
	// 		return errors.New("missing required field 'r' in transaction")
	// 	}
	// 	itx.R = (*big.Int)(dec.R)
	// 	if dec.S == nil {
	// 		return errors.New("missing required field 's' in transaction")
	// 	}
	// 	itx.S = (*big.Int)(dec.S)
	// 	withSignature := itx.V.Sign() != 0 || itx.R.Sign() != 0 || itx.S.Sign() != 0
	// 	if withSignature {
	// 		if err := sanityCheckSignature(itx.V, itx.R, itx.S, false); err != nil {
	// 			return err
	// 		}
	// 	}

	// case *QuoteTxType:
	// 	var itx Quote
	// 	inner = &itx
	// 	if dec.From != nil {
	// 		itx.From = dec.From
	// 	}
	// 	itx.Data = *dec.Input
	// 	if dec.V == nil {
	// 		return errors.New("missing required field 'v' in transaction")
	// 	}
	// 	itx.V = uint256.MustFromBig((*big.Int)(dec.V))
	// 	if dec.R == nil {
	// 		return errors.New("missing required field 'r' in transaction")
	// 	}
	// 	itx.R = uint256.MustFromBig((*big.Int)(dec.R))
	// 	if dec.S == nil {
	// 		return errors.New("missing required field 's' in transaction")
	// 	}
	// 	itx.S = uint256.MustFromBig((*big.Int)(dec.S))
	// 	withSignature := itx.V.Sign() != 0 || itx.R.Sign() != 0 || itx.S.Sign() != 0
	// 	if withSignature {
	// 		if err := sanityCheckSignature(itx.V.ToBig(), itx.R.ToBig(), itx.S.ToBig(), false); err != nil {
	// 			return err
	// 		}
	// 	}

	default:
		return ErrTxTypeNotSupported
	}

	// Now set the inner transaction.
	tx.setDecoded(inner, 0)

	// TODO: check hash here?
	return nil
}

func sanityCheckSignature(v *big.Int, r *big.Int, s *big.Int, maybeProtected bool) error {
	var plainV byte

	// if v.BitLen() <= 8 {
	// 	plainV = byte(v.Uint64() - 27)
	// } else {
	// 	// Here we assume the signature is in EIP-155 format.
	// 	// You might want to do more checks to confirm this.
	// 	plainV = byte(v.Uint64() - 35)
	// }

	if !cryptoocax.ValidateSignatureValues(plainV, r, s) {
		return ErrInvalidSig
	}

	return nil
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28 && v != 1 && v != 0
	}
	// anything not 27 or 28 is considered protected
	return true
}
