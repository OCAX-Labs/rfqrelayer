package types

// import (
// 	"bytes"
// 	"crypto/sha256"
// 	"encoding/gob"

// 	"github.com/ethereum/go-ethereum/common"
// )

// type Hasher[T any] interface {
// 	Hash(T) common.Hash
// }

// type BlockHasher struct{}

// func (BlockHasher) Hash(b *Header) common.Hash {
// 	h := sha256.Sum256(b.Bytes())
// 	return common.Hash(h)
// }

// type TxHasher struct{}

// func (TxHasher) Hash(tx *Transaction) common.Hash {
// 	// buf := make([]byte, 8)
// 	// binary.LittleEndian.PutUint64(buf, uint64(tx.Nonce))
// 	// data := append(buf, tx.Data...)

// 	buf := &bytes.Buffer{}
// 	if err := gob.NewEncoder(buf).Encode(tx); err != nil {
// 		panic(err)
// 	}

// 	return common.Hash(sha256.Sum256(buf.Bytes()))
// }
