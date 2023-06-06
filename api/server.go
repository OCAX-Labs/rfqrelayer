package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"net/http"
	"strconv"
	"time"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	"github.com/go-kit/log"
	"github.com/gorilla/websocket"
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

	// Secure this for production in terms of allowed origins
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	clients = make(map[*websocket.Conn]bool) // connected clients
	mutex   = &sync.Mutex{}
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

type Header struct {
	Version        uint64      `json:"version" gencodec:"required"`
	TxHash         common.Hash `json:"txRoot" gencodec:"required"`
	ParentHash     common.Hash `json:"parentHash"`
	Timestamp      uint64      `json:"timestamp" gencodec:"required"`
	Height         *big.Int    `json:"height" gencodec:"required"`
	BlockSignature string      `json:"blockSignature" gencodec:"required"`
	Hash           string      `json:"hash"` // new field
}

type ServerConfig struct {
	Logger     log.Logger
	ListenAddr string
}

type Server struct {
	txChan chan *types.Transaction
	// newRFQChan chan *types.RFQRequest // <- add this line

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
	// go func() {
	// 	for newRFQRequest := range s.newRFQChan {
	// 		s.broadcastNewRFQRequest(newRFQRequest)
	// 	}
	// }()

	e.GET("/block/:hashorid", s.handleGetBlock)
	e.GET("/headers/:height", s.handleGetHeaders)
	e.GET("/tx/:hash", s.handleGetTx)
	e.POST("/tx", s.handlePostTx)
	e.GET("/rfqs", s.handleGetRFQRequests)
	// e.GET("/openrfqs", s.handleGetOpenRFQRequests)

	// websockets for broadcast of RFQRequest
	e.GET("/ws", s.handleWsConnections)

	return e.Start(s.ListenAddr)
}

func (s *Server) handlePostTx(c echo.Context) error {
	txRequest := new(types.Transaction)
	if err := c.Bind(txRequest); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	if err := txRequest.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	fmt.Printf("tx.Data: %+v\n", txRequest.Data())
	fmt.Printf("tx.From: %+v\n", txRequest.From().Hex())

	// so we are not constrained by block time - we save this in a custom table
	// to allow fast access to the db
	s.bc.WriteRFQTxs(txRequest)

	// Broadcast to the blockchain
	s.txChan <- txRequest

	return c.JSON(http.StatusAccepted, txRequest)
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

func (s *Server) handleGetHeaders(c echo.Context) error {
	height := c.Param("height")
	h, err := strconv.Atoi(height)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	hHeight := big.NewInt(int64(h))
	header, err := s.bc.GetBlockHeader(hHeight)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	return c.JSON(http.StatusOK, intoJSONHeader(header))
}

func (s *Server) handleGetRFQRequests(c echo.Context) error {
	rfqRequests, err := s.bc.GetRFQRequests()
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	return c.JSON(http.StatusOK, rfqRequests)
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

func intoJSONHeader(header *types.Header) Header {
	return Header{
		Version:        header.Version,
		TxHash:         header.TxHash,
		ParentHash:     header.ParentHash,
		Timestamp:      uint64(header.Timestamp),
		Height:         header.Height,
		BlockSignature: hex.EncodeToString(header.BlockSignature),
		Hash:           header.Hash().Hex(),
	}
}

func (s *Server) handleWsConnections(c echo.Context) error {
	fmt.Println("WEBSOCKETS: ws connection")
	ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()

	mutex.Lock()
	clients[ws] = true
	mutex.Unlock()

	// Start a separate goroutine that waits for messages from the client.
	go func() {
		defer func() {
			mutex.Lock()
			delete(clients, ws)
			mutex.Unlock()
		}()

		for {
			var msg string
			err := ws.ReadJSON(&msg)
			if err != nil {
				s.Logger.Log("level", "error", "msg", err)
				break
			}
			// For now, just print out the received messages.
			fmt.Printf("received: %v\n", msg)
		}
	}()

	// Wait for the connection to close.
	// refactor: hack to keep the connection open
	for {
		if _, ok := clients[ws]; !ok {
			break
		}
		time.Sleep(1 * time.Second)
	}

	return nil
}

func (s *Server) BroadcastOpenRFQ(openRFQ *types.OpenRFQ) {
	data, err := json.Marshal(openRFQ) // Replace with your RFQRequest marshalling code
	if err != nil {
		s.Logger.Log("level", "error", "error", err)
		return
	}

	for client := range clients {
		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			s.Logger.Log("level", "error", "error", err)
			client.Close()
			delete(clients, client)
		}
	}
}

// func (tx *Transaction) Validate() error {

// 	// Logic here to unwrap the transaction wrapper and validate the fields
// 	fmt.Println("Unwrapping and validating transaction wrapper")

// 	if err := r.validateRequestorId(); err != nil {
// 		return err
// 	}

// 	// if err := validateAddress(common.HexToAddress(r.inner.From()); err != nil {
// 	// 	return err
// 	// }

// 	// if err := r.validateBaseToken(); err != nil {
// 	// 	return err
// 	// }

// 	// if err := r.validateQuoteToken(); err != nil {
// 	// 	return err
// 	// }

// 	// Repeat similar validations for other fields...
// 	return nil
// }

// func (r *types.Transaction) validateRequestorId() error {
// 	// Logic here to validate the requestor ID field

// 	// match, _ := regexp.MatchString("^[0-9]+$", r.RequestorId)
// 	// if !match {
// 	// 	return errInvalidRequestorId
// 	// }
// 	return nil
// }

// func (r *types.Transaction) validateBaseToken() error {
// 	// Logic here    to check and validate that the quote token details are correct
// 	// TODO: Once onboarding requirements are finalized we can add more validation here

// 	// Check that the quote token address is a valid Ethereum address
// 	// if err := validateAddress(r.Data.BaseToken.Address); err != nil {
// 	// 	return err
// 	// }

// 	// // // Check that the quote token symbol is not empty
// 	// if r.Data.BaseToken.Symbol == "" {
// 	// 	return errors.New("base token symbol cannot be empty")
// 	// }

// 	// // // check decimals
// 	// if r.Data.BaseToken.Decimals > 18 {
// 	// 	return errors.New("base token decimals must be between 0 and 18")
// 	// }

// 	return nil
// }

// func (r *types.Transaction) validateQuoteToken() error {
// 	// Logic here    to check and validate that the quote token details are correct
// 	// TODO: Once onboarding requirements are finalized we can add more validation here

// 	// Check that the quote token address is a valid Ethereum address
// 	// if err := validateAddress(r.Data.QuoteToken.Address); err != nil {
// 	// 	return err
// 	// }

// 	// // // Check that the quote token symbol is not empty
// 	// if r.Data.QuoteToken.Symbol == "" {
// 	// 	return errors.New("quote token symbol cannot be empty")
// 	// }

// 	// // // check decimals
// 	// if r.Data.QuoteToken.Decimals > 18 {
// 	// 	return errors.New("quote token decimals must be between 0 and 18")
// 	// }

// 	return nil
// }

// func (r *TransactionWrapper) createTransactionFromRequest() *types.Transaction {
// 	fmt.Println("creating transaction from request")
// 	// fmt.Printf(" from: %s\n", common.HexToAddress(r.From).String())
// 	// from := common.HexToAddress(r.From)
// 	// data := r.Data
// 	// signature := &cryptoocax.Signature{
// 	// 	V: &r.V.Int,
// 	// 	R: &r.R.Int,
// 	// 	S: &r.S.Int,
// 	// }

// 	// rfqRequest := types.NewRFQRequest(from, &data)
// 	// tx := types.NewTx(rfqRequest)
// 	// signer := types.NewSigner()
// 	// signedTx, err := tx.WithSignature(signer, signature.ToBytes())
// 	// if err != nil {
// 	// 	fmt.Println("error signing transaction", err)
// 	// 	return nil
// 	// }

// 	// fmt.Printf("signed tx: %v\n", signedTx)
// 	// // Logic here to create a transaction from the request data
// 	return &types.Transaction{}
// }

// func validateAddress(addr common.Address) error {
// 	if !common.IsHexAddress(addr.String()) {
// 		return errInvalidAddress
// 	}

// 	// check if the address has mixed case, then it should be checksum
// 	if hasMixedCase(addr.String()) && !common.IsHexAddress(addr.Hex()) {
// 		return errInvalidChecksum
// 	}

// 	return nil
// }

// // helper function to determine if the address has mixed case
// func hasMixedCase(s string) bool {
// 	return strings.ToLower(s) != s && strings.ToUpper(s) != s
// }
