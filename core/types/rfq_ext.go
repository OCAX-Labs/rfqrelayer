package types

import (
	"go/types"
	"math/big"
	"time"
)

type RfqData struct {
	RequestorID string `json:"requestorId"`

	// the token contract address and details for the token the trader is selling
	BaseTokenAddr     string `json:"baseTokenAddress,omitempty"`
	BaseTokenSymbol   string `json:"baseTokenSymbol"`
	BaseTokenDecimals int    `json:"baseTokenDecimals,omitempty"`

	// empty if the trader is buying, otherwise the amount of base token the trader is selling
	BaseTokenAmount string `json:"baseTokenAmount,omitempty"`

	// the token contract and details for the token the trader is buying
	QuoteTokenAddr     string `json:"quoteTokenAddress,omitempty"`
	QuoteTokenSymbol   string `json:"quoteTokenSymbol"`
	QuoteTokenDecimals int    `json:"quoteTokenDecimals,omitempty"`

	// empty if the trader is selling, otherwise the amount of quote token the trader is buying
	QuoteTokenAmount string `json:"quoteTokenAmount,omitempty"`

	FeesBps   int       `json:"feesBps,omitempty"`
	RfqExpiry time.Time `json:"rfqExpiry,omitempty"`
}

type SecretShare struct {
}

type QuoteBroadcast struct {
	// Todo depends on what we want to QuoteBroadcast
	encryptKey   SecretShare
	RfqId        string
	Volume       *big.Int
	TokenName    string
	TokenAddress string
	ChainId      int
	AuctionEnd   time.Time
}

type RfqMsg struct {
	MsgType string  `json:"type"`
	Data    RfqData `json:"data"`
}

type QuoteDatMsg struct {
	// the id of the RFQ this quote is responding to
	RfqId string `json:"rfq_id"`

	BaseToken  string `json:"base_token"`
	QuoteToken string `json:"quote_token"`

	BaseTokenAmount  string `json:"base_token_amount"`
	QuoteTokenAmount string `json:"quote_token_amount"`

	QuoteExpiry time.Time `json:"quote_expiry"`
}

type BidQuoteData struct {
	types.Signature
	QuoterId     string
	Volume       *big.Int
	Price        *big.Int
	TokenName    string
	TokenAddress string
	Expiry       time.Time
	RfqId        string
}

type AskQuoteData struct {
	types.Signature
	QuoterId     string
	Volume       *big.Int
	Price        *big.Int
	TokenName    string
	TokenAddress string
	Expiry       time.Time
	RfqId        string
}

type QuoteMsg struct {
	MsgType string    `json:"type"`
	Data    QuoteData `json:"data"`
}

type RFQSnapshot struct {
	// should contain everything for the MPC nodes to complete there work

	RFQId string

	Bids []BidQuoteData
	Asks []AskQuoteData
}
