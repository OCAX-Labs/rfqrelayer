package network

import (
	"testing"

	"github.com/OCAX-labs/rfqrelayer/core/types"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/OCAX-labs/rfqrelayer/utils"
	"github.com/stretchr/testify/assert"
)

var testKey = cryptoocax.GeneratePrivateKey()

func TestTxMaxLength(t *testing.T) {
	p := NewTxPool(1)
	p.Add(utils.NewRandomTransaction(testKey.PublicKey()))
	assert.Equal(t, 1, p.all.Count())

	p.Add(utils.NewRandomTransaction(testKey.PublicKey()))
	p.Add(utils.NewRandomTransaction(testKey.PublicKey()))
	p.Add(utils.NewRandomTransaction(testKey.PublicKey()))
	tx := utils.NewRandomTransaction(testKey.PublicKey())
	p.Add(tx)
	assert.Equal(t, 1, p.all.Count())
	// assert.True(t, p.Contains(tx.Hash(types.TxHasher{})))
}

func TestTxPoolAdd(t *testing.T) {
	p := NewTxPool(11)
	n := 10

	for i := 1; i <= n; i++ {
		tx := utils.NewRandomTransaction(testKey.PublicKey())
		p.Add(tx)
		// cannot add twice
		p.Add(tx)

		assert.Equal(t, i, p.PendingCount())
		assert.Equal(t, i, p.pending.Count())
		assert.Equal(t, i, p.all.Count())
	}
}

func TestTxPoolMaxLength(t *testing.T) {
	maxLen := 10
	p := NewTxPool(maxLen)
	n := 100
	txx := []*types.Transaction{}

	for i := 0; i < n; i++ {
		tx := utils.NewRandomTransaction(testKey.PublicKey())
		p.Add(tx)

		if i > n-(maxLen+1) {
			txx = append(txx, tx)
		}
	}

	assert.Equal(t, p.all.Count(), maxLen)
	assert.Equal(t, len(txx), maxLen)

	// for _, tx := range txx {
	// 	assert.True(t, p.Contains(tx.Hash(types.TxHasher{})))
	// }
}

func TestTxSortedMapFirst(t *testing.T) {
	m := NewTxSortedMap()
	first := utils.NewRandomTransaction(testKey.PublicKey())
	m.Add(first)
	m.Add(utils.NewRandomTransaction(testKey.PublicKey()))
	m.Add(utils.NewRandomTransaction(testKey.PublicKey()))
	m.Add(utils.NewRandomTransaction(testKey.PublicKey()))
	m.Add(utils.NewRandomTransaction(testKey.PublicKey()))
	assert.Equal(t, first, m.First())
}

func TestTxSortedMapAdd(t *testing.T) {
	m := NewTxSortedMap()
	n := 100

	for i := 0; i < n; i++ {
		tx := utils.NewRandomTransaction(testKey.PublicKey())
		m.Add(tx)
		// cannot add the same twice
		m.Add(tx)

		assert.Equal(t, m.Count(), i+1)
		// assert.True(t, m.Contains(tx.Hash(types.TxHasher{})))
		assert.Equal(t, len(m.lookup), m.txx.Len())
		// assert.Equal(t, m.Get(tx.Hash(types.TxHasher{})), tx)
	}

	m.Clear()
	assert.Equal(t, m.Count(), 0)
	assert.Equal(t, len(m.lookup), 0)
	assert.Equal(t, m.txx.Len(), 0)
}

func TestTxSortedMapRemove(t *testing.T) {
	m := NewTxSortedMap()

	tx := utils.NewRandomTransaction(testKey.PublicKey())
	m.Add(tx)
	assert.Equal(t, m.Count(), 1)

	m.Remove(tx.Hash())
	assert.Equal(t, m.Count(), 0)
	assert.False(t, m.Contains(tx.Hash()))
}
