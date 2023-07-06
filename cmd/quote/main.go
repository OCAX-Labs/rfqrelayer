package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
)

const (
	AppUrl = "http://localhost:9999"
)

func main() {

	rfqTxRef := flag.String("rfqTxRef", "", "the RFQ tx reference being quoted")
	privateKey := cryptoocax.GeneratePrivateKey()
	publicKey := privateKey.PublicKey()
	addr := publicKey.Address()
	checkSumAddr := addr.Hex()
	addr = common.HexToAddress(checkSumAddr)
	flag.Parse()
	if *rfqTxRef == "" {
		log.Fatal("Please provide a valid RFQ tx reference")
	}

	url := AppUrl + "/openRFQs/" + *rfqTxRef
	fmt.Printf("Sending request to: %s\n", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	defer resp.Body.Close()

	data := result["data"].(map[string]interface{})
	rfqRequest := data["rfqRequest"].(map[string]interface{})
	baseToken := rfqRequest["baseToken"].(map[string]interface{})
	quoteToken := rfqRequest["quoteToken"].(map[string]interface{})
	baseTokenAddr := baseToken["address"].(string)
	quoteTokenAddr := quoteToken["address"].(string)
	baseTokenSymbol := baseToken["symbol"].(string)
	quoteTokenSymbol := quoteToken["symbol"].(string)
	baseTokenDecimals := uint64(baseToken["decimals"].(float64))
	quoteTokenDecimals := uint64(quoteToken["decimals"].(float64))
	baseTokenAmount := big.NewInt(int64(rfqRequest["baseTokenAmount"].(float64)))

	quoteData := types.QuoteData{
		QuoterId:        result["from"].(string),
		RFQTxHash:       common.HexToHash(*rfqTxRef),
		QuoteExpiryTime: uint64(10 * 60 * 1000),
		BaseToken: &types.BaseToken{
			Address:  common.HexToAddress(baseTokenAddr),
			Symbol:   baseTokenSymbol,
			Decimals: baseTokenDecimals,
		},
		QuoteToken: &types.QuoteToken{
			Address:  common.HexToAddress(quoteTokenAddr),
			Symbol:   quoteTokenSymbol,
			Decimals: quoteTokenDecimals,
		},
		BaseTokenAmount:      baseTokenAmount,
		QuoteTokenAmount:     big.NewInt(0),
		EncryptionPublicKeys: []*cryptoocax.PublicKey{},
	}

	quote := types.NewQuote(common.HexToAddress(checkSumAddr), &quoteData)
	tx := types.NewTx(quote)
	signedTx, err := tx.Sign(privateKey)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}
	v, r, s := signedTx.RawSignatureValues()
	fmt.Printf(`{
		"from": "%s",
		"data": {
			"quoterId": "%s",
			"rfqTxHash": "%s",
			"quoteExpiryTime": %d,
			"baseToken": {
				"address": "%s",
				"symbol": "%s",
				"decimals": %d
			},
			"quoteToken": {
				"address": "%s",
				"symbol": "%s",
				"decimals": %d
			},
			"baseTokenAmount": %d,
			"quoteTokenAmount": %d,
			"encryptionPublicKeys": []
		},
		"v": %d,
		"r": %d,
		"s": %d
	}\n`,
		addr.Hex(),
		addr.Hex(),
		quoteData.RFQTxHash.Hex(),
		quoteData.QuoteExpiryTime,
		quoteData.BaseToken.Address.Hex(),
		quoteData.BaseToken.Symbol,
		quoteData.BaseToken.Decimals,
		quoteData.QuoteToken.Address.Hex(),
		quoteData.QuoteToken.Symbol,
		quoteData.QuoteToken.Decimals,
		quoteData.BaseTokenAmount,
		quoteData.QuoteTokenAmount,
		v,
		r,
		s,
	)
}
