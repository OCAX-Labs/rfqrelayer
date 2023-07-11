package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"sync"

	"net/http"
	"strconv"
	"time"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
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

type RFQRequestBody struct {
	From string              `json:"from"`
	Data *types.SignableData `json:"data"`
}

type QuoteBody struct {
	From            string           `json:"from"`
	Data            *types.QuoteData `json:"data"`
	SignatureString string           `json:"signature"`
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
	PrivateKey *cryptoocax.PrivateKey
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
	e.POST("/rfqs", s.handlePostRFQRequest)
	e.GET("/openRFQs", s.handleGetOpenRFQRequests)
	e.GET("/openRFQs/:txHash", s.handleGetOpenRFQRequest)
	e.GET("/closedRFQs", s.handleGetClosedRFQRequests)
	e.GET("/quotes/:rfqTxHash", s.handleGetAuctionQuotes)
	e.POST("/quotes", s.handlePostQuote)

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

	return c.JSON(http.StatusOK, intoJSONRFQ(rfqRequests))
}

func (s *Server) handleGetOpenRFQRequests(c echo.Context) error {
	rfqRequests, err := s.bc.GetOpenRFQRequests()
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	return c.JSON(http.StatusOK, intoJSONOpenRFQS(rfqRequests))
}

func (s *Server) handleGetOpenRFQRequest(c echo.Context) error {
	hash := c.Param("txHash")
	b, err := hex.DecodeString(hash)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	hashFromBytes := common.HashFromBytes(b)

	rfqRequest, err := s.bc.GetOpenRFQByHash(hashFromBytes)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, intoJSONOpenRFQ(rfqRequest))
}

func (s *Server) handlePostRFQRequest(c echo.Context) error {
	requestBody := new(RFQRequestBody)

	// Start by reading the request body into a byte slice
	body, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	// Then use json.Unmarshal to unmarshal the byte slice into signableData
	err = json.Unmarshal(body, requestBody)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	signableData := requestBody.Data
	if err := signableData.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	rfqRequest := types.NewRFQRequest(s.PrivateKey.PublicKey().Address(), signableData)
	txRFQRequest := types.NewTx(rfqRequest)
	signedTx, err := txRFQRequest.Sign(*s.PrivateKey)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	s.bc.WriteRFQTxs(signedTx)

	// Broadcast to the blockchain
	s.txChan <- signedTx

	return c.JSON(http.StatusAccepted, signedTx)

}

func (s *Server) handleGetClosedRFQRequests(c echo.Context) error {
	rfqRequests, err := s.bc.GetClosedRFQRequests()
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, intoJSONOpenRFQS(rfqRequests))
}

func (s *Server) handleGetAuctionQuotes(c echo.Context) error {
	rfqTxHash := c.Param("rfqTxHash")
	b, err := hex.DecodeString(rfqTxHash)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	hashFromBytes := common.HashFromBytes(b)
	auctionQuotes, err := s.bc.GetAuctionQuotes(hashFromBytes)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	return c.JSON(http.StatusOK, auctionQuotes)
}

func (s *Server) handlePostQuote(c echo.Context) error {
	decoder := json.NewDecoder(c.Request().Body)
	var quoteBody QuoteBody
	err := decoder.Decode(&quoteBody)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	rfqTxHash := quoteBody.Data.RFQTxHash
	openRFQ, err := s.bc.GetOpenRFQByHash(rfqTxHash)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: "RFQ does not exist or has already expired"})
	}
	if time.Now().Unix() > openRFQ.Data.RFQEndTime {
		return c.JSON(http.StatusBadRequest, APIError{Error: "RFQ is no longer open"})
	}
	quoteData := quoteBody.Data
	if err := quoteData.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	signature, err := cryptoocax.DeserializeSigFromHexString(quoteBody.SignatureString)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	quote := types.NewQuote(common.HexToAddress(quoteBody.From), quoteBody.Data)
	signer := types.NewSigner()
	quoteTx := types.NewTx(quote)

	signedTx, err := quoteTx.WithSignature(signer, signature.ToBytes())
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	fmt.Printf("HANDLER signedTx: %+v\n", signedTx)

	err = signedTx.Verify()
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	// update the openRFQ in memory
	s.bc.WriteRFQTxs(signedTx)
	s.txChan <- signedTx

	s.bc.UpdateActiveRFQ(rfqTxHash, quote)

	return c.JSON(http.StatusCreated, openRFQ)
}

// Check that the RFQ is still open and not completed
// If it is not completed add the quote to the in memory rfq

// If the openRFQ is completed ie, RFQEndTime has passed, then return an error
// If the openRFQ is not completed, then add the quote to the db

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

func intoJSONOpenRFQS(openRFQs []*types.OpenRFQ) []types.OpenRFQ {
	openRFQsJSON := make([]types.OpenRFQ, len(openRFQs))
	for i, openRFQ := range openRFQs {
		openRFQsJSON[i] = intoJSONOpenRFQ(openRFQ)
	}
	return openRFQsJSON
}

func intoJSONOpenRFQ(openRFQ *types.OpenRFQ) types.OpenRFQ {
	// dataJson, err := openRFQ.Data.JSON()
	// if err != nil {
	// 	panic(err)
	// }
	return types.OpenRFQ{
		From: openRFQ.From,
		Data: openRFQ.Data,
		V:    openRFQ.V,
		R:    openRFQ.R,
		S:    openRFQ.S,
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

func (s *Server) BroadcastTx(tx *types.Transaction, txType byte) {
	fmt.Println("WEBSOCKETS: broadcasting  tx")
	var data []byte
	var err error
	switch txType {
	case types.OpenRFQTxType:
		data, err = json.Marshal(tx.EmbeddedData().(*types.RFQData)) // Replace with your RFQRequest marshalling code
		if err != nil {
			s.Logger.Log("level", "error", "broadcast error", err)
			return
		}
	case types.QuoteTxType:
		data, err = json.Marshal(tx.EmbeddedData().(*types.QuoteData))
	case types.ClosedRFQTxType:
		data, err = json.Marshal(tx.EmbeddedData().(types.OpenRFQ))
	default:
		s.Logger.Log("level", "error", "broadcast error", "invalid tx type")
	}
	if err != nil {
		s.Logger.Log("level", "error", "broadcast error", err)
		return
	}
	s.broadcastToWS(data)
}

func (s *Server) broadcastToWS(data []byte) {
	for client := range clients {
		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			s.Logger.Log("level", "error", "error", err)
			client.Close()
			delete(clients, client)
		}
	}
}
