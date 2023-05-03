package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// hasherPool holds LegacyKeccak256 hashers for rlpHash.
// sync.Pool is a pool of temporary objects that can be reused to avoid allocation.
var hasherPool = sync.Pool{
	New: func() interface{} { return sha3.NewLegacyKeccak256() },
}

// encodeBufferPool holds temporary encoder buffers for DeriveSha and TX encoding.
// These buffers are used to store the serialized form of the data before hashing.
var encodeBufferPool = sync.Pool{
	New: func() interface{} { return new(bytes.Buffer) },
}

// rlpHash encodes x and hashes the encoded bytes.
// It is a helper function that hashes the RLP encoding of whatever is passed to it.
func rlpHash(x interface{}) (h common.Hash) {
	sha := hasherPool.Get().(crypto.KeccakState) // Get a hasher from the pool.
	defer hasherPool.Put(sha)                    // Put the hasher back into the pool when done.
	sha.Reset()                                  // Reset the hasher.
	rlp.Encode(sha, x)                           // Encode the input into the hasher.
	sha.Read(h[:])                               // Read the hash result into h.
	return h
}

// prefixedRlpHash writes the prefix into the hasher before rlp-encoding x.
// It's used for typed transactions.
func prefixedRlpHash(prefix byte, x interface{}) (h common.Hash) {
	sha := hasherPool.Get().(crypto.KeccakState)
	defer hasherPool.Put(sha)
	sha.Reset()
	sha.Write([]byte{prefix}) // Write the prefix into the hasher.
	rlp.Encode(sha, x)        // RLP-encode the input into the hasher.
	sha.Read(h[:])            // Read the hash result into h.
	return h
}

// TrieHasher is an interface for types that can be used to hash tries.
// It is implemented by OcaxHasher.
type TrieHasher interface {
	Reset()
	Update([]byte, []byte) error
	Hash() common.Hash
}

// OcaxHasher is a type that hashes data using the SHA3 Shake256 algorithm.
type OcaxHasher struct {
	hasher crypto.KeccakState
}

// NewOcaxHasher creates a new OcaxHasher.
func NewOcaxHasher() *OcaxHasher {
	return &OcaxHasher{
		hasher: crypto.NewKeccakState(), // Create a new SHA3 Shake256 hasher.
	}
}

// Reset resets the hasher to its initial state.
func (h *OcaxHasher) Reset() {
	h.hasher.Reset()
}

// Update updates the hash with a new key-value pair.
// It first writes the length of the key and the key itself, then the length of the value and the value itself.
func (h *OcaxHasher) Update(key, value []byte) error {
	if err := binary.Write(h.hasher, binary.BigEndian, uint32(len(key))); err != nil {
		return err
	}
	if _, err := h.hasher.Write(key); err != nil {
		return err
	}
	if err := binary.Write(h.hasher, binary.BigEndian, uint32(len(value))); err != nil {
		return err
	}
	if _, err := h.hasher.Write(value); err != nil {
		return err
	}
	return nil
}

// Hash returns the final hash of the updated state.
func (h *OcaxHasher) Hash() common.Hash {
	var hash common.Hash
	if _, err := h.hasher.Read(hash[:]); err != nil {
		panic(errors.New("SimpleTrieHasher: cannot read hash"))
	}
	return hash
}

// DerivableList is the input to DeriveSha.
// It is implemented by the 'Transactions' and 'Receipts' types.
// This is internal, do not use these methods.
type DerivableList interface {
	Len() int
	EncodeIndex(int, *bytes.Buffer)
}

func encodeForDerive(list DerivableList, i int, buf *bytes.Buffer) []byte {
	buf.Reset()
	list.EncodeIndex(i, buf)
	// It's really unfortunate that we need to do perform this copy.
	// StackTrie holds onto the values until Hash is called, so the values
	// written to it must not alias.
	return common.CopyBytes(buf.Bytes())
}

// DeriveSha creates the tree hashes of transactions, receipts, and withdrawals in a block header.
func DeriveSha(list DerivableList, hasher TrieHasher) common.Hash {
	hasher.Reset()

	valueBuf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(valueBuf)

	// StackTrie requires values to be inserted in increasing hash order, which is not the
	// order that `list` provides hashes in. This insertion sequence ensures that the
	// order is correct.
	//
	// The error returned by hasher is omitted because hasher will produce an incorrect
	// hash in case any error occurs.
	var indexBuf []byte
	for i := 1; i < list.Len() && i <= 0x7f; i++ {
		indexBuf = rlp.AppendUint64(indexBuf[:0], uint64(i))
		value := encodeForDerive(list, i, valueBuf)
		hasher.Update(indexBuf, value)
	}
	if list.Len() > 0 {
		indexBuf = rlp.AppendUint64(indexBuf[:0], 0)
		value := encodeForDerive(list, 0, valueBuf)
		hasher.Update(indexBuf, value)
	}
	for i := 0x80; i < list.Len(); i++ {
		indexBuf = rlp.AppendUint64(indexBuf[:0], uint64(i))
		value := encodeForDerive(list, i, valueBuf)
		hasher.Update(indexBuf, value)
	}
	return hasher.Hash()
}
