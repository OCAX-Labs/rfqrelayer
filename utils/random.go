package utils

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"math/big"

	"testing"
	"time"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/stretchr/testify/assert"
)

func RandomBytes(size int) []byte {
	token := make([]byte, size)
	rand.Read(token)
	return token
}

func RandomHash() common.Hash {
	return common.HashFromBytes(RandomBytes(32))
}

// GenerateRandomStringID generates a random hexadecimal string of length n.
func GenerateRandomStringID(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}

	id := hex.EncodeToString(b)
	return id[:n] // return the first n characters
}

// NewRandomTransaction return a new random transaction without signature.
func NewRandomTransaction(pubKey cryptoocax.PublicKey) *types.Transaction {
	from := pubKey.Address()
	inner := &types.RFQRequest{
		From: from,
		Data: randomRFQ(),
	}

	tx := types.NewTx(inner)

	return tx
}

func randomRFQ() *types.SignableData {
	// generate a random number to be used as the requestor id
	rand, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		panic(err)
	}
	// Create an instance of SignableData
	signableData := types.SignableData{
		RequestorId:     "119",
		BaseTokenAmount: big.NewInt(rand.Int64()),
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

	return &signableData
}

func NewRandomTransactionWithSignature(t *testing.T, privKey cryptoocax.PrivateKey) *types.Transaction {
	pubKey := privKey.PublicKey()
	tx := NewRandomTransaction(pubKey)
	signedTx, err := tx.Sign(privKey)
	assert.Nil(t, err)
	return signedTx
}

func NewRandomBlock(t *testing.T, height uint64, prevBlockHash common.Hash) *types.Block {
	blockSigner := cryptoocax.GeneratePrivateKey()
	txSigner := cryptoocax.GeneratePrivateKey()
	tx1 := NewRandomTransactionWithSignature(t, txSigner)
	tx2 := NewRandomTransactionWithSignature(t, txSigner)
	txs := types.Transactions{tx1, tx2}
	blHeight := big.NewInt(int64(height))
	header := &types.Header{
		Version:    1,
		ParentHash: prevBlockHash,
		Height:     blHeight,
		Timestamp:  uint64(time.Now().UnixNano()),
	}
	b := types.NewBlock(header, txs, blockSigner.PublicKey())

	return b
}

func NewRandomBlockWithSignature(t *testing.T, pk cryptoocax.PrivateKey, height uint64, prevHash common.Hash) *types.Block {
	b := NewRandomBlock(t, height, prevHash)
	assert.Nil(t, b.Sign(pk))

	return b
}
