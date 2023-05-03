package core

import (
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core/rawdb"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	"github.com/OCAX-labs/rfqrelayer/db/pebble"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/go-kit/log"
)

type ChainInterface interface {
	GetTxByHash(hash common.Hash) (*types.Transaction, error)
	GetBlockByHash(hash common.Hash) (*types.Block, error)
	GetBlock(height *big.Int) (*types.Block, error)
	// GetLatestBlock() *types.Block
}

type Blockchain struct {
	logger  log.Logger
	db      *pebble.Database
	lock    sync.RWMutex
	headers []*types.Header
	// blocks  []*Block
	txStore map[common.Hash]*types.Transaction
	// blockStore map[common.Hash]*Block
	genesisBlock *types.Block

	validator Validator // TODO: convert to interface

	currentBlock atomic.Pointer[types.Header] // Current head of the chain
	bodyCache    *lru.Cache[common.Hash, *types.Body]
	bodyRLPCache *lru.Cache[common.Hash, rlp.RawValue]
}

func NewBlockchain(l log.Logger, genesis *types.Block, db *pebble.Database, validator bool) (*Blockchain, error) {
	bc := &Blockchain{
		headers: []*types.Header{},
		db:      db,
		logger:  l,
		// blockStore: make(map[common.Hash]*Block),
		txStore: make(map[common.Hash]*types.Transaction),
	}
	if validator {
		bc.validator = NewBlockValidator(bc)
		err := bc.addBlockWithoutValidation(genesis)
		if err != nil {
			return nil, err
		}
	}

	// bc.genesisBlock = bc.GetBlockByNumber(0)
	// if bc.genesisBlock == nil {
	// 	return nil, ErrNoGenesis
	// }

	bc.currentBlock.Store(nil)

	return bc, nil
}

func (bc *Blockchain) SetValidator(v Validator) {
	bc.validator = v
}

func (bc *Blockchain) VerifyBlock(b *types.Block) error {
	if b == nil {
		return fmt.Errorf("malformed block: is nil")
	}
	if b.Header() == nil {
		return fmt.Errorf("malformed block: header is nil")
	}

	if bc.validator != nil {
		if err := bc.validator.ValidateBlock(b); err != nil {
			return err
		}
	}

	// validate transactions
	for _, tx := range b.Transactions() {
		if err := tx.Verify(); err != nil {
			fmt.Printf("Failed to verify transaction: %+v\n", tx)
			return err
		}

		bc.logger.Log("msg", "Parsing Transactions", "len", len(tx.Data()), "hash", tx.Hash())
	}
	bc.logger.Log("msg", "Verifying block for commit to chain ...", "height", b.Height().String())

	return bc.addBlockWithoutValidation(b)
}

func (bc *Blockchain) GetBlockByHash(hash common.Hash) (*types.Block, error) {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	// block, ok := bc.blockStore[hash]
	// if !ok {
	// 	return nil, fmt.Errorf("block with hash [%x] not found", hash)
	// }
	return &types.Block{}, nil
}

func (bc *Blockchain) GetTxByHash(hash common.Hash) (*types.Transaction, error) {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	tx, ok := bc.txStore[hash]
	if !ok {
		return nil, fmt.Errorf("transaction with hash [%x] not found", hash)
	}
	return tx, nil
}

func (bc *Blockchain) GetBlock(height *big.Int) (*types.Block, error) {
	currHeight := bc.Height()
	reqHeight := height.Int64()
	if height.Cmp(currHeight) == 1 {
		return nil, fmt.Errorf("blockchain height [%s] is less than requested height [%d]", currHeight.String(), reqHeight)
	}
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	blockHeader, err := bc.GetHeader(height)
	if err != nil {
		return nil, err
	}
	block := rawdb.ReadBlock(bc.db, blockHeader.Hash(), uint64(reqHeight))
	if block == nil {
		return nil, fmt.Errorf("block with hash [%x] not found", blockHeader.Hash())
	}

	return block, nil
}

func (bc *Blockchain) GetHeader(height *big.Int) (*types.Header, error) {
	return bc.headers[height.Int64()], nil
}

// CurrentBlock retrieves the current head block of the canonical chain. The
// block is retrieved from the blockchain's internal cache.
func (bc *Blockchain) CurrentBlock() *types.Header {
	return bc.currentBlock.Load()
}

func (bc *Blockchain) HasBlock(height *big.Int) bool {
	currHeight := bc.Height()
	switch height.Cmp(currHeight) {
	case 1:
		return false
	case 0:
		return true
	case -1:
		return true
	}
	return false
}

func (bc *Blockchain) Height() *big.Int {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	headLength := len(bc.headers)
	indexHeight := big.NewInt(int64(headLength - 1))

	return indexHeight
}

func (bc *Blockchain) Headers() []*types.Header {
	return bc.headers
}

func (bc *Blockchain) addBlockWithoutValidation(b *types.Block) error {
	// bc.lock.Lock()

	bc.headers = append(bc.headers, b.Header())

	// Store block with block hash as key
	// blockKey := b.Hash().Bytes()
	// blockBytes, err := rlp.EncodeToBytes(b)
	// if err != nil {
	// 	return err
	// }
	// fmt.Printf("BBLOCK => Writing block to db: %+v\n", b)
	rawdb.WriteBlock(bc.db, b)

	bc.logger.Log("msg", "Block saved to the kv store", "hash", b.Hash(), "height", b.Height().String(), "txs", len(b.Transactions()))

	// Also store the block header separately.
	// key := append(append([]byte("h"), encodeBlockNumber(number)...), blockKey...)

	// headerKey := append(blockKey, byte{"header"})
	// err = db.Put(headerKey, rlp.EncodeToBytes(block.Header()))
	// if err != nil {
	// 	log.Fatalf("Failed to write block header: %v", err)
	// }

	// bc.blockStore[b.Hash(BlockHasher{})] = b

	// for _, tx := range b.Transactions() {
	// 	// bc.txStore[tx.Hash(TxHasher{})] = tx
	// 	// fmt .Printf("TODO: save these transactions in db: %+v\n", tx)
	// }

	// bc.lock.Unlock()
	bc.currentBlock.Store(b.Header())

	if len(bc.headers) == 1 {
		bc.logger.Log("msg", "Genesis block added to the chain", "hash", b.Hash(), "height", b.Height().String())
		bc.genesisBlock = b
		return nil
	}

	bc.logger.Log(
		"msg", "BlockAdd",
		"hash", b.Hash(),
		"height", b.Height().String(),
		"txs", len(b.Transactions()),
	)
	return nil
}
