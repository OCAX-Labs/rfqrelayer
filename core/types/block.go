package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	// EmptyTxsHash is the known hash of the empty transaction set.
	EmptyTxsHash = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
)

type Header struct {
	Version        uint64      `json:"version" gencodec:"required"`   // Version of the OCAX protocol
	TxHash         common.Hash `json:"txRoot" gencodec:"required"`    // Transactions merkle root
	ParentHash     common.Hash `json:"parentHash"`                    // Hash of the previous block header
	Timestamp      uint64      `json:"timestamp" gencodec:"required"` // Timestamp of the block in seconds since the epoch
	Height         *big.Int    `json:"height" gencodec:"required"`    // Block height
	BlockSignature []byte      `json:"blockHash" gencodec:"required"` // Hash of the block
}

// field type overrides for gencodec
type headerMarshaling struct {
	Height    *hexutil.Big
	TimeStamp hexutil.Uint64
	Hash      common.Hash `json:"hash"` // adds call to Hash() in MarshalJSON
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
func (h *Header) Hash() common.Hash {
	return rlpHash(h)
}

func (h *Header) Bytes() []byte {
	encodedHeaderBytes, err := rlp.EncodeToBytes(h)
	if err != nil {
		log.Fatalf("Failed to RLP encode header: %v", err)
	}

	return encodedHeaderBytes
}

var headerSize = common.StorageSize(reflect.TypeOf(Header{}).Size())

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	return headerSize + common.StorageSize(h.Height.BitLen()/8)
}

// EmptyBody returns true if there is no additional 'body' to complete the header
// that is: no transactions, no uncles and no withdrawals.
func (h *Header) EmptyBody() bool {
	return h.TxHash == EmptyTxsHash
}

// Body is a simple (mutable, non-safe) data container for storing and moving
// a block's data contents (transactions and uncles) together.
type Body struct {
	Transactions []*Transaction
	Validator    cryptoocax.PublicKey
}

func (b *Body) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{b.Transactions, b.Validator})
}

func (b *Body) DecodeRLP(s *rlp.Stream) error {
	// Start reading list
	_, err := s.List()
	if err != nil {
		return err
	}

	var transactions []*Transaction
	if err := s.Decode(&transactions); err != nil {
		return err
	}

	var validator cryptoocax.PublicKey
	if err := s.Decode(&validator); err != nil {
		return err
	}

	b.Transactions = transactions
	b.Validator = validator

	return s.ListEnd()
}

// func (b *Body) DecodeRLP(s *rlp.Stream) error {
// 	var data struct {
// 		Transactions [][]byte
// 		Validator    cryptoocax.PublicKey
// 	}

// 	if err := s.Decode(&data); err != nil {
// 		return err
// 	}

// 	b.Transactions = make([]*Transaction, len(data.Transactions))
// 	for i, txBytes := range data.Transactions {
// 		tx := &Transaction{}
// 		if err := rlp.DecodeBytes(txBytes, tx); err != nil {
// 			return err
// 		}
// 		b.Transactions[i] = tx
// 	}

// 	b.Validator = data.Validator

// 	return nil
// }

type Block struct {
	header *Header

	transactions Transactions
	Validator    cryptoocax.PublicKey

	// caching
	hash atomic.Value
	size atomic.Value

	// cache of the block hash
}

func NewBlock(h *Header, txs Transactions, pubkey cryptoocax.PublicKey) *Block {
	validator := pubkey
	b := &Block{
		header:    CopyHeader(h),
		Validator: validator,
	}

	if txs.Len() == 0 {
		h.TxHash = EmptyTxsHash
		b.header.TxHash = EmptyTxsHash
		b.transactions = make(Transactions, 0)
	} else {
		b.transactions = make(Transactions, txs.Len())
		copy(b.transactions, txs)
	}
	b.header.TxHash = b.MerkleRoot()
	return b
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// WithBody returns a new block with the given transaction and uncle contents.
func (b *Block) WithBody(transactions Transactions, validator cryptoocax.PublicKey) *Block {
	block := &Block{
		header:       CopyHeader(b.header),
		transactions: make([]*Transaction, len(transactions)),
		Validator:    validator,
	}
	copy(block.transactions, transactions)
	return block
}

func (b *Block) WithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

func CopyHeader(h *Header) *Header {
	cpy := *h
	cpy.Height = new(big.Int)
	if h.Height != nil {
		cpy.Height.Set(h.Height)
	}
	return &cpy
}

func NewBlockFromPrevHeader(prevHeader *Header, txs Transactions) (*Block, error) {
	// txHash, _ := CalculateTxHash(txx)

	newBlock := NewBlock(prevHeader, txs, nil)
	bHeight := new(big.Int).Set(prevHeader.Height)
	bHeight.Add(bHeight, big.NewInt(1))
	newBlock.header.Height = bHeight
	newBlock.header.ParentHash = prevHeader.Hash()
	newBlock.header.Timestamp = uint64(time.Now().UnixNano())

	// calculate tx hash
	if len(txs) == 0 {
		newBlock.header.TxHash = EmptyTxsHash
	} else {
		newBlock.header.TxHash = newBlock.MerkleRoot()
		newBlock.transactions = make(Transactions, len(txs))
		copy(newBlock.transactions, txs)
	}

	return newBlock, nil
}

func (b *Block) AddTransaction(tx *Transaction) {
	b.transactions = append(b.transactions, tx)
}

func (b *Block) Sign(pk cryptoocax.PrivateKey) error {
	sig, err := pk.Sign(b.Hash().Bytes())
	if err != nil {
		return err
	}

	b.Validator = pk.PublicKey()
	b.header.BlockSignature = sig.ToBytes()

	return nil
}

func (b *Block) Verify() error {
	if b.header.BlockSignature == nil {
		return fmt.Errorf("no signature")
	}

	sigRSV, err := cryptoocax.DeserializeSig(b.header.BlockSignature)
	if err != nil {
		return err
	}
	if !sigRSV.Verify(b.Validator, b.Hash().Bytes()) {
		return fmt.Errorf("invalid signature")
	}

	hash := b.MerkleRoot()
	if hash != b.header.TxHash {
		return fmt.Errorf("block [%s] data hash mismatch", b.Hash())
	}

	return nil
}

type Encoder[T any] interface {
	Encode(T) error
}

type Decoder[T any] interface {
	Decode(T) error
}

func (b *Block) Decode(dec Decoder[*Block]) error {
	var decodedBlock Block
	var buf bytes.Buffer
	s := rlp.NewStream(&buf, 0)
	err := decodedBlock.DecodeRLP(s)
	if err != nil {
		return err
	}

	return dec.Decode(b)
}

func (b *Block) Encode(enc Encoder[*Block]) error {
	return enc.Encode(b)
}

// "external" block encoding. used for eth protocol, etc.
type extblock struct {
	Header    *Header
	Txs       []*Transaction
	Validator cryptoocax.PublicKey
}

func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.transactions, b.Validator = eb.Header, eb.Txs, eb.Validator

	// If the transactions slice is empty, set it to nil
	if len(b.transactions) == 0 {
		b.transactions = make(Transactions, 0)
	}

	// If the BlockSignature is an empty slice, set it to nil
	if len(b.header.BlockSignature) == 0 {
		b.header.BlockSignature = nil
	}

	b.size.Store(rlp.ListSize(size))
	return nil
}

// EncodeRLP serializes b into the Ethereum RLP block format.
func (b *Block) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extblock{
		Header:    b.header,
		Txs:       b.transactions,
		Validator: b.Validator,
	})
}

func (b *Block) Hash() common.Hash {
	if hashHead := b.hash.Load(); hashHead != nil {
		return hashHead.(common.Hash)
	}

	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, b.header.Version)

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, b.header.Timestamp)

	v := crypto.Keccak256(
		versionBytes,
		b.header.ParentHash.Bytes(),
		b.header.TxHash.Bytes(),
		b.header.Height.Bytes(),
		timestampBytes,
	)

	var hash common.Hash
	copy(hash[:], v)
	b.hash.Store(hash)
	return b.hash.Load().(common.Hash)
}

func (b *Block) Header() *Header { return CopyHeader(b.header) }

// Body returns the non-header content of the block.
func (b *Block) Body() *Body { return &Body{b.transactions, b.Validator} }

func (b *Block) Transactions() Transactions { return b.transactions }

func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}

func (b *Block) Height() *big.Int        { return new(big.Int).Set(b.header.Height) }
func (b *Block) Timestamp() uint64       { return b.header.Timestamp }
func (b *Block) HeightU64() uint64       { return b.header.Height.Uint64() }
func (b *Block) ParentHash() common.Hash { return b.header.ParentHash }
func (b *Block) TxHash() common.Hash     { return b.header.TxHash }
func (b *Block) Version() uint64         { return b.header.Version }

func (b *Block) MerkleRoot() common.Hash {
	var hashes []common.Hash

	for _, tx := range b.transactions {
		hashes = append(hashes, tx.Hash())
	}

	// If no transactions, return empty hash
	if len(hashes) == 0 {
		return EmptyTxsHash
	}

	for len(hashes) > 1 {
		if len(hashes)%2 == 1 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var newLevel []common.Hash
		for i := 0; i < len(hashes); i += 2 {
			var appendHash common.Hash
			appendBytes := crypto.Keccak256(hashes[i][:], hashes[i+1][:])
			copy(appendHash[:], appendBytes)
			newLevel = append(newLevel, appendHash)
		}

		hashes = newLevel
	}

	return hashes[0]
}

func CalculateTxHash(txs []*Transaction) (hash common.Hash, err error) {
	buf := &bytes.Buffer{}

	for _, tx := range txs {
		// if err = tx.Encode(NewRLPTxEncoder(buf)); err != nil {
		// 	return
		// }
		fmt.Println(tx)
	}

	hash = sha256.Sum256((buf.Bytes()))

	return
}

type writeCounter uint64

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}
