package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"time"

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
	baseTokenAmountFloat := big.NewFloat(rfqRequest["baseTokenAmount"].(float64))
	baseTokenAmount := new(big.Int)
	baseTokenAmountFloat.Int(baseTokenAmount) //
	bidPrice, askPrice := generateRandomPrice(1500)

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
		BidPrice:             bidPrice,
		AskPrice:             askPrice,
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
			"bidPrice": %d,
			"askPrice": %d,
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
		quoteData.BidPrice,
		quoteData.AskPrice,
		v,
		r,
		s,
	)
}

// helper function to generate random bid and ask prices
// the function takes an integer (i) as input and returns a random number that
// is between 0.9*i and 1.1*i the returned number is then converted to a big Int
// and multiplied by 1e18 to add 18 decimals

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func generateRandomPrice(indic int) (bid *big.Int, ask *big.Int) {
	lower := 0.9 * float64(indic)
	upper := 1.1 * float64(indic)
	// generate random number between 0.9*indic and 1.1*indic
	randPrice := rng.Float64()*(upper-lower) + lower
	bidPrice := 0.95 * randPrice

	// convert to big int and add 18 decimals
	askFloat := big.NewFloat(randPrice)
	askMultiplier := big.NewFloat(1e18)
	askProduct := new(big.Float).Mul(askFloat, askMultiplier)
	ask = new(big.Int)
	askProduct.Int(ask) // convert to *big.Int, ignoring any fractional part

	bidFloat := big.NewFloat(bidPrice)
	bidMultiplier := big.NewFloat(1e18)
	bidProduct := new(big.Float).Mul(bidFloat, bidMultiplier)
	bid = new(big.Int)
	bidProduct.Int(bid) // convert to *big.Int, ignoring any fractional part

	return bid, ask
}
