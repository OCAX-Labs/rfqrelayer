package api

import (
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"math/big"

	"net/http"
	"strconv"
	"time"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	"github.com/go-kit/log"
	"github.com/labstack/echo/v4"
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
	tx := &types.Transaction{}
	if err := gob.NewDecoder(c.Request().Body).Decode(&tx); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	s.txChan <- tx

	return nil

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
		// block, err := s.bc.GetBlock(uint64(height))
		// if err != nil {
		// 	return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
		// }

		block := &types.Block{}

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
