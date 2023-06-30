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

type RFQRequest struct {
	From string
	Data string
	V    *big.Int
	R    *big.Int
	S    *big.Int
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

	// Now that the RFQ is validated we can create an "auction wrapper" used to receive that auctions quotes from the blockchain
	// this wrapper is an OpenRFQ struct that is stored in the db with a copy kept in memory the OpenRFQ can only be updated by quotes submitted
	// before the RFQ deadline - once the deadline is reached the openRFQ is closed and the records are sent to the matching engine - for determining
	// the best auction quotes

	// openRFQ := types.NewOpenRFQ(txRequest)

	// s.c

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

	return c.JSON(http.StatusOK, intoJSONRFQ(rfqRequests))
}

func intoJSONRFQ(rfqRequests []*types.RFQRequest) []RFQRequest {
	rfqRequestsJSON := make([]RFQRequest, len(rfqRequests))
	for i, rfqRequest := range rfqRequests {
		rfqRequestsJSON[i] = intoJSONRFQRequest(rfqRequest)
	}
	return rfqRequestsJSON
}

func intoJSONRFQRequest(rfqRequest *types.RFQRequest) RFQRequest {
	dataJson, err := rfqRequest.Data.JSON()
	if err != nil {
		panic(err)
	}

	return RFQRequest{
		From: rfqRequest.From.Hex(),
		Data: string(dataJson),
		V:    rfqRequest.V,
		R:    rfqRequest.R,
		S:    rfqRequest.S,
	}
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
	fmt.Println("WEBSOCKETS: broadcasting open RFQ")
	data, err := json.Marshal(openRFQ) // Replace with your RFQRequest marshalling code

	if err != nil {
		s.Logger.Log("level", "error", "broadcasterror", err)
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
