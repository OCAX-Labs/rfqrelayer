package rawdb

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	db "github.com/OCAX-labs/rfqrelayer/rfqdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var logger log.Logger

func WriteBlock(db db.KeyValueWriter, block *types.Block) {
	WriteBody(db, block.Header().Hash(), block.HeightU64(), block.Body())
	WriteHeader(db, block.Header())
}

// WriteBody stores a block body into the database.
func WriteBody(db db.KeyValueWriter, hash common.Hash, number uint64, body *types.Body) {
	data, err := rlp.EncodeToBytes(body)

	if err != nil {
		level.Error(logger).Log("message", "Failed to rlp encode body", "err", err)
	}
	WriteBodyRLP(db, hash, number, data)
}

// WriteBodyRLP stores an RLP encoded block body into the database.
func WriteBodyRLP(db db.KeyValueWriter, hash common.Hash, number uint64, rlp rlp.RawValue) {
	if err := db.Put(blockBodyKey(number, hash), rlp); err != nil {
		level.Error(logger).Log("message", "Failed to store block body", "err", err)
	}
}

func WriteTransaction(db db.KeyValueWriter, tx *types.Transaction) error {
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}

	return db.Put(transactionKey(tx.Hash()), data)
}
func WriteOpenRFQTx(db db.KeyValueWriter, tx *types.Transaction) (common.Hash, error) {
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return common.Hash{}, err
	}
	hash := transactionKey(tx.ReferenceTxHash())
	return common.BytesToHash(hash), db.Put(hash, data)

}

func WriteHeader(db db.KeyValueWriter, header *types.Header) {
	var (
		hash   = header.Hash()
		number = header.Height.Uint64()
	)
	// Write the hash -> number mapping
	WriteHeaderNumber(db, hash, number)

	// Write the encoded header
	data, err := rlp.EncodeToBytes(header)
	if err != nil {
		level.Error(logger).Log("message", "Failed to RLP encode header", "err", err)
	}
	key := headerKey(number, hash)
	// fmt.Printf("Writing header using key: %+v and data: %+v\n", key, data)
	if err := db.Put(key, data); err != nil {
		level.Error(logger).Log("message", "Failed to store header", "err", err)
	}
}

func WriteHeaderNumber(db db.KeyValueWriter, hash common.Hash, number uint64) {
	key := headerHeightKey(hash)
	enc := encodeBlockHeight(number)
	if err := db.Put(key, enc); err != nil {
		level.Error(logger).Log("message", "Failed to store hash to number mapping", "err", err)
	}
}

func ReadTransaction(db db.KeyValueReader, hash common.Hash) (*types.Transaction, error) {
	data, _ := db.Get(transactionKey(hash))
	if len(data) == 0 {
		return nil, errors.New("transaction not found")
	}

	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(data, tx); err != nil {
		return nil, err
	}

	return tx, nil
}

// HasBody verifies the existence of a block body corresponding to the hash.
func HasBody(db db.Reader, hash common.Hash, number uint64) bool {
	if has, err := db.Has(blockBodyKey(number, hash)); !has || err != nil {
		return false
	}
	return true
}

// ReadBodyRLP retrieves the block body (transactions and uncles) in RLP encoding.
func ReadBodyRLP(db db.Reader, hash common.Hash, number uint64) rlp.RawValue {
	var data []byte
	data, err := db.Get(blockBodyKey(number, hash))
	if err != nil {
		level.Error(logger).Log("msg", "Failed to read block body", "err", err)
	}
	return data
}

// // ReadBody retrieves the block body corresponding to the hash.
// func ReadBody(db db.Reader, hash common.Hash, number uint64) *types.Body {
// 	fmt.Printf("ReadBody key: %+v\n", blockBodyKey(number, hash))
// 	data := ReadBodyRLP(db, hash, number)
// 	fmt.Printf("ReadBody data: %+v\n", data)
// 	if len(data) == 0 {
// 		return nil
// 	}
// 	body := new(types.Body)
// 	if err := rlp.Decode(bytes.NewReader(data), body); err != nil {
// 		fmt.Errorf("Failed to decode block body: %v", err)
// 		// l
// 		// evel.Error(logger).Log("msg", "Invalid block body RLP", "hash", hash, "err", err)
// 		return nil
// 	}
// 	return body
// }

func ReadBody(db db.Reader, hash common.Hash, number uint64) *types.Body {
	data := ReadBodyRLP(db, hash, number)
	if len(data) == 0 {
		return nil
	}
	body := new(types.Body)
	if err := rlp.Decode(bytes.NewReader(data), body); err != nil {
		fmt.Errorf("Failed to decode block body: %v", err)
		return nil
	}
	return body
}

// ReadHeaderRLP retrieves a block header in its raw RLP database encoding.
func ReadHeaderRLP(db db.Reader, hash common.Hash, number uint64) rlp.RawValue {
	var data []byte
	// fmt.Printf("ReadHeaderRLP key: %+v\n", headerKey(number, hash))
	data, _ = db.Get(headerKey(number, hash))
	return data
}

// ReadHeader retrieves the block header corresponding to the hash.
func ReadHeader(db db.Reader, hash common.Hash, number uint64) *types.Header {
	data := ReadHeaderRLP(db, hash, number)
	if len(data) == 0 {
		return nil
	}
	header := new(types.Header)
	if err := rlp.Decode(bytes.NewReader(data), header); err != nil {
		level.Error(logger).Log("Invalid block header RLP", "hash", hash, "err", err)
		return nil
	}
	return header
}

// ReadBlock retrieves an entire block corresponding to the hash, assembling it
// back from the stored header and body. If either the header or body could not
// be retrieved nil is returned.
// func ReadBlock(db db.Reader, hash common.Hash, number uint64) *types.Block {
// 	header := ReadHeader(db, hash, number)
// 	if header == nil {
// 		return nil
// 	}
// 	fmt.Printf("ReadBlock header: %+v\n", header)
// 	fmt.Printf("ReadBlock header hash: %+v, height: %d\n", header.Hash(), number)
// 	body := ReadBody(db, hash, number)
// 	fmt.Printf("ReadBlock body: %+v\n", body)
// 	return types.NewBlockWithHeader(header).WithBody(body.Transactions, body.Validator)
// }

func ReadBlock(db db.Reader, hash common.Hash, number uint64) *types.Block {
	header := ReadHeader(db, hash, number)
	if header == nil {
		return nil
	}
	body := ReadBody(db, hash, number)
	if body == nil {
		return types.NewBlockWithHeader(header)
	}
	return types.NewBlockWithHeader(header).WithBody(body.Transactions, body.Validator)
}

// Fetch all OpenRFQ transactions from the database

// func ReadOpenRFQTx(db db.Iteratee) ([]*types.Transaction, error) {
// 	var txs []*types.Transaction
// 	iter := db.NewIterator(types.OpenRFQTxType, nil)
// 	for iter.First(); iter.Valid(); iter.Next() {
// 		tx := new(types.Transaction)
// 		if err := rlp.DecodeBytes(iter.Value(), tx); err != nil {
// 			return nil, err
// 		}
// 		txs = append(txs, tx)
// 	}
// 	iter.Release()
// 	return txs, iter.Error()
// }
