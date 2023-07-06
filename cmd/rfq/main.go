package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/OCAX-labs/rfqrelayer/utils"
)

type RFQRequest struct {
	From common.Address     `json:"from"`
	Data types.SignableData `json:"data"`
	V    *big.Int           `json:"v"`
	R    *big.Int           `json:"r"`
	S    *big.Int           `json:"s"`
}

func main() {
	privateKey := cryptoocax.GeneratePrivateKey()
	publicKey := privateKey.PublicKey()

	addr := publicKey.Address()
	checkSumAddr := addr.Hex()
	addr = common.HexToAddress(checkSumAddr)

	amountTokens := big.NewInt(199)
	amountTokens = amountTokens.Mul(amountTokens, big.NewInt(1e18)) // add 18 decimals

	uid := utils.GenerateRandomStringID(10)

	signableData := types.SignableData{
		RequestorId:     uid,
		BaseTokenAmount: amountTokens,
		BaseToken: &types.BaseToken{
			Address:  common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
			Symbol:   "VFG",
			Decimals: 18,
		},
		QuoteToken: &types.QuoteToken{
			Address:  common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
			Symbol:   "USDC",
			Decimals: 6,
		},
		RFQDurationMs: 60000,
	}

	rfqRequest := types.NewRFQRequest(addr, &signableData)
	tx := types.NewTx(rfqRequest)
	signedTx, err := tx.Sign(privateKey)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}
	v, r, s := signedTx.RawSignatureValues()
	fmt.Printf(`{
    "from": "%s",
    "data": {
        "requestorId": "%s",
        "baseTokenAmount": %s,
        "baseToken": {
            "Address": "%s",
            "Symbol": "%s",
            "Decimals": %d
        },
        "quoteToken": {
            "Address": "%s",
            "Symbol": "%s",
            "Decimals": %d
        },
        "rfqDurationMs": %d
    },
    "v": "%s",
    "r": "%s",
    "s": "%s"
}\n`,
		addr.Hex(),
		uid,
		amountTokens.String(),
		signableData.BaseToken.Address.Hex(),
		signableData.BaseToken.Symbol,
		signableData.BaseToken.Decimals,
		signableData.QuoteToken.Address.Hex(),
		signableData.QuoteToken.Symbol,
		signableData.QuoteToken.Decimals,
		signableData.RFQDurationMs,
		v.String(),
		r.String(),
		s.String(),
	)
}
