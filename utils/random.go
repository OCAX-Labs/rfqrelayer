package utils

import (
	"math/big"
	"math/rand"

	"fmt"
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

// NewRandomTransaction return a new random transaction without signature.
func NewRandomTransaction(pubKey cryptoocax.PublicKey) *types.Transaction {
	from := pubKey.Address()
	inner := &types.RFQRequest{
		From: from,
		Data: []byte(fmt.Sprintf("random tx %d", rand.Int63())),
	}

	tx := types.NewTx(inner)

	return tx
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
