package types

import (
	"go/types"
	"math/big"
	"time"
)

type RfqData struct {
	RequestorID string `json:"requestor_id"`

	// the token contract address and details for the token the trader is selling
	BaseTokenAddr     string `json:"base_token_address,omitempty"`
	BaseTokenSymbol   string `json:"base_token_symbol"`
	BaseTokenDecimals int    `json:"base_token_decimals,omitempty"`

	// empty if the trader is buying, otherwise the amount of base token the trader is selling
	BaseTokenAmount string `json:"base_token_amount,omitempty"`

	// the token contract and details for the token the trader is buying
	QuoteTokenAddr     string `json:"quote_token_address,omitempty"`
	QuoteTokenSymbol   string `json:"quote_token_symbol"`
	QuoteTokenDecimals int    `json:"quote_token_decimals,omitempty"`

	// empty if the trader is selling, otherwise the amount of quote token the trader is buying
	QuoteTokenAmount string `json:"quote_token_amount,omitempty"`

	FeesBps   int       `json:"fees_bps,omitempty"`
	RfqExpiry time.Time `json:"rfq_expiry,omitempty"`
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

type QuoteData struct {
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
