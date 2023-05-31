package api

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"net/http"
	"strconv"
	"time"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/go-kit/log"
	"github.com/labstack/echo/v4"
)

var (
	errInvalidAddress     = errors.New("invalid Ethereum address")
	errInvalidChecksum    = errors.New("invalid Ethereum address checksum")
	errInvalidSymbol      = errors.New("invalid token symbol")
	errInvalidDecimals    = errors.New("invalid token decimals")
	errInvalidAmount      = errors.New("invalid token amount")
	errInvalidDuration    = errors.New("invalid RFQ duration")
	errInvalidRequestorId = errors.New("invalid requestor ID")
	errInvalidTimestamp   = errors.New("invalid timestamp")
)

type TxResponse struct {
	TxCount uint
	Hashes  []string
}

type APIError struct {
	Error string
}

type Block struct {
	Hash       string
	Version    uint64
	TxHash     string
	ParentHash string
	Height     *big.Int
	Timestamp  time.Time
	Validator  string
	Signature  string

	TxResponse TxResponse
}

type TransactionWrapper struct {
	Time  time.Time         `json:"time"`
	Inner RFQRequestWrapper `json:"inner"`
	// Include other fields from Transaction as needed
}

type RFQRequestWrapper struct {
	From string                `json:"from"`
	Data types.SignableRFQData `json:"data"`
	V    *big.Int              `json:"v"`
	R    *big.Int              `json:"r"`
	S    *big.Int              `json:"s"`
}

type ServerConfig struct {
	Logger     log.Logger
	ListenAddr string
}

type Server struct {
	txChan chan *types.Transaction
	ServerConfig
	bc core.ChainInterface
}

func NewServer(cfg ServerConfig, bc core.ChainInterface, txChan chan *types.Transaction) *Server {
	return &Server{
		ServerConfig: cfg,
		bc:           bc,
		txChan:       txChan,
	}
}

func (s *Server) Start() error {
	e := echo.New()

	e.GET("/block/:hashorid", s.handleGetBlock)
	e.GET("/tx/:hash", s.handleGetTx)
	e.POST("/tx", s.handlePostTx)

	return e.Start(s.ListenAddr)
}

func (s *Server) handlePostTx(c echo.Context) error {
	request := new(TransactionWrapper)
	if err := c.Bind(request); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	if err := request.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	// Create transaction based on request data
	// and send to channel
	tx := request.createTransactionFromRequest()
	s.txChan <- tx

	return c.JSON(http.StatusAccepted, tx)
}

func (s *Server) handleGetTx(c echo.Context) error {
	hash := c.Param("hash")

	b, err := hex.DecodeString(hash)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	hashFromBytes := common.HashFromBytes(b)
	tx, err := s.bc.GetTxByHash(hashFromBytes)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, tx)
}

func (s *Server) handleGetBlock(c echo.Context) error {
	hashOrID := c.Param("hashorid")

	height, err := strconv.Atoi(hashOrID)
	if err == nil {
		fmt.Println("height", height)
		block, err := s.bc.GetBlock(big.NewInt(int64(height)))
		if err != nil {
			return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
		}

		return c.JSON(http.StatusOK, intoJSONBlock(block))
	}

	b, err := hex.DecodeString(hashOrID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	block, err := s.bc.GetBlockByHash(common.HashFromBytes(b))
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, intoJSONBlock(block))
}

func intoJSONBlock(block *types.Block) Block {
	txResponse := TxResponse{
		TxCount: uint(len(block.Transactions())),
		Hashes:  make([]string, len(block.Transactions())),
	}

	for i, tx := range block.Transactions() {
		txResponse.Hashes[i] = tx.Hash().String()
	}

	return Block{
		Hash:       block.Hash().String(),
		Version:    block.Version(),
		Height:     block.Height(),
		TxHash:     block.TxHash().String(),
		ParentHash: block.ParentHash().String(),
		Timestamp:  time.Unix(0, int64(block.Timestamp())),
		Validator:  block.Validator.Address().String(),
		TxResponse: txResponse,
	}
}

func (r *TransactionWrapper) Validate() error {
	if err := r.validateRequestorId(); err != nil {
		return err
	}

	if err := validateAddress(common.HexToAddress(r.Inner.From)); err != nil {
		return err
	}

	if err := r.validateBaseToken(); err != nil {
		return err
	}

	if err := r.validateQuoteToken(); err != nil {
		return err
	}

	// Repeat similar validations for other fields...
	return nil
}

func (r *TransactionWrapper) validateRequestorId() error {
	// Logic here to validate the requestor ID field

	// match, _ := regexp.MatchString("^[0-9]+$", r.RequestorId)
	// if !match {
	// 	return errInvalidRequestorId
	// }
	return nil
}

func (r *TransactionWrapper) validateBaseToken() error {
	// Logic here    to check and validate that the quote token details are correct
	// TODO: Once onboarding requirements are finalized we can add more validation here

	// Check that the quote token address is a valid Ethereum address
	if err := validateAddress(r.Inner.Data.BaseToken.Address); err != nil {
		return err
	}

	// // Check that the quote token symbol is not empty
	if r.Inner.Data.BaseToken.Symbol == "" {
		return errors.New("base token symbol cannot be empty")
	}

	// // check decimals
	if r.Inner.Data.BaseToken.Decimals < 0 || r.Inner.Data.BaseToken.Decimals > 18 {
		return errors.New("base token decimals must be between 0 and 18")
	}

	return nil
}

func (r *TransactionWrapper) validateQuoteToken() error {
	// Logic here    to check and validate that the quote token details are correct
	// TODO: Once onboarding requirements are finalized we can add more validation here

	// Check that the quote token address is a valid Ethereum address
	if err := validateAddress(r.Inner.Data.QuoteToken.Address); err != nil {
		return err
	}

	// // Check that the quote token symbol is not empty
	if r.Inner.Data.QuoteToken.Symbol == "" {
		return errors.New("quote token symbol cannot be empty")
	}

	// // check decimals
	if r.Inner.Data.QuoteToken.Decimals < 0 || r.Inner.Data.QuoteToken.Decimals > 18 {
		return errors.New("quote token decimals must be between 0 and 18")
	}

	return nil
}

func (r *TransactionWrapper) createTransactionFromRequest() *types.Transaction {
	from := common.HexToAddress(r.Inner.From)
	data := r.Inner.Data
	signature := &cryptoocax.Signature{
		V: r.Inner.V,
		R: r.Inner.R,
		S: r.Inner.S,
	}
	fmt.Printf("Signature: %+v\n", signature)
	fmt.Printf("Data: %+v\n", data)

	rfqRequest := types.NewTransaction(from, data)
	tx := types.NewTx(rfqRequest)
	signer := types.NewSigner()
	signedTx, err := tx.WithSignature(signer, signature.ToBytes())
	if err != nil {
		fmt.Println("error signing transaction", err)
		return nil
	}

	// // Logic here to create a transaction from the request data
	return signedTx
}

func validateAddress(addr common.Address) error {
	if !common.IsHexAddress(addr.String()) {
		return errInvalidAddress
	}

	// check if the address has mixed case, then it should be checksummed
	if hasMixedCase(addr.String()) && !common.IsHexAddress(addr.Hex()) {
		return errInvalidChecksum
	}

	return nil
}

// helper function to determine if the address has mixed case
func hasMixedCase(s string) bool {
	return strings.ToLower(s) != s && strings.ToUpper(s) != s
}
