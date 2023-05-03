package types

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
)

func TestNewBlock(t *testing.T) {
	header := &Header{
		Version:    1,
		ParentHash: common.BytesToHash([]byte("parent hash")),
		Timestamp:  uint64(time.Now().Unix()),
		Height:     big.NewInt(1),
	}

	txs := Transactions{}

	block := NewBlock(header, txs, nil)

	assert.Equal(t, header, block.Header())
	assert.Equal(t, txs, block.Transactions())
	assert.Equal(t, block.header.TxHash, block.MerkleRoot())
}

func TestBlockHeaderHash(t *testing.T) {
	header := &Header{
		Version:        uint64(1),
		TxHash:         common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		ParentHash:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Timestamp:      1,
		Height:         big.NewInt(1),
		BlockSignature: nil,
	}

	hash := header.Hash()
	assert.NotNil(t, hash)
}

func TestAddTransaction(t *testing.T) {
	key := cryptoocax.GeneratePrivateKey()
	pubKey := key.PublicKey()
	from := pubKey.Address()
	block := NewBlockWithHeader(&Header{
		Version:    1,
		ParentHash: common.BytesToHash([]byte("parent hash")),
		Timestamp:  uint64(time.Now().Unix()),
		Height:     big.NewInt(1),
	})

	tx := NewTx(&RFQRequest{
		From: from,
		Data: []byte("Hello, world!"),
	})

	block.AddTransaction(tx)

	assert.Equal(t, tx, block.Transactions()[0])
}

func TestBlockSignAndVerify(t *testing.T) {
	privateKey := cryptoocax.GeneratePrivateKey()
	pubKey := privateKey.PublicKey()

	header := &Header{
		Version:        1,
		TxHash:         common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		ParentHash:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Timestamp:      1,
		Height:         big.NewInt(1),
		BlockSignature: nil,
	}

	block := NewBlock(header, nil, pubKey)

	err := block.Sign(privateKey)
	assert.Nil(t, err)

	err = block.Verify()
	assert.Nil(t, err)
}

func TestBlockEncodeDecodeRLP(t *testing.T) {
	privateKey := cryptoocax.GeneratePrivateKey()
	pubKey := privateKey.PublicKey()

	header := &Header{
		Version:        1,
		TxHash:         common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		ParentHash:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Timestamp:      1,
		Height:         big.NewInt(1),
		BlockSignature: nil,
	}

	block := NewBlock(header, nil, pubKey)
	assert.NotNil(t, block.Validator)
	buf := bytes.NewBuffer(nil)
	err := block.EncodeRLP(buf)
	assert.Nil(t, err)

	decodedBlock := &Block{}
	stream := rlp.NewStream(buf, 0)
	err = decodedBlock.DecodeRLP(stream)
	assert.Nil(t, err)

	assert.Equal(t, block.header, decodedBlock.header)
	assert.Equal(t, block.transactions, decodedBlock.transactions)
	assert.Equal(t, block.Validator, decodedBlock.Validator)
	assert.Equal(t, block.hash, decodedBlock.hash)

}

func TestAddressEncodeDecode(t *testing.T) {
	addr := common.HexToAddress("0x0a648918E6039C8b84864Ff0Aa287B5455cF8aE7")

	var buffer bytes.Buffer
	err := rlp.Encode(&buffer, addr)
	if err != nil {
		t.Fatalf("Failed to encode Address: %v", err)
	}

	var decodedAddr common.Address
	err = rlp.Decode(&buffer, &decodedAddr)
	if err != nil {
		t.Fatalf("Failed to decode Address: %v", err)
	}

	// Check if decodedAddr matches addr
	if decodedAddr != addr {
		t.Fatalf("Addresses do not match, got: %v, want: %v", decodedAddr, addr)
	}
}

func TestBodyEncodeDecode(t *testing.T) {
	privKey := cryptoocax.GeneratePrivateKey()
	tx1 := NewTx(&RFQRequest{
		From: privKey.PublicKey().Address(),
		Data: []byte("Hello, world!"),
	})

	body := &Body{
		Transactions: Transactions{tx1},
	}

	var buffer bytes.Buffer
	err := body.EncodeRLP(&buffer)
	if err != nil {
		t.Fatalf("Failed to encode Body: %v", err)
	}

	var decodedReq Body
	s := rlp.NewStream(&buffer, 0)
	err = decodedReq.DecodeRLP(s)
	// err = rlp.Decode(&buffer, &decodedReq)
	if err != nil {
		t.Fatalf("Failed to decode Body: %v", err)
	}

	// Check if decodedReq matches req
}

// TestBlockEncodeDecodeWithTransactions checks if blocks with transactions are correctly encoded and decoded.
func TestBlockEncodeDecodeWithTransactions(t *testing.T) {
	key := cryptoocax.GeneratePrivateKey()
	pubKey := key.PublicKey()
	from := pubKey.Address()

	transaction := NewTx(&RFQRequest{
		From: from,
		Data: []byte("Hello, world!"),
	})
	txs := Transactions{transaction, transaction}
	// txs := Transactions{}
	header := &Header{
		Version:    1,
		ParentHash: common.BytesToHash([]byte("parent hash")),
		Timestamp:  uint64(time.Now().Unix()),
		Height:     big.NewInt(1),
	}

	block := NewBlock(header, txs, pubKey)

	var buffer bytes.Buffer
	err := block.EncodeRLP(&buffer)
	if err != nil {
		t.Fatalf("Failed to encode block: %v", err)
	}

	var decodedBlock Block
	rlpStream := rlp.NewStream(&buffer, 0)
	err = decodedBlock.DecodeRLP(rlpStream)
	if err != nil {
		t.Fatalf("Failed to decode block: %v", err)
	}

	if len(decodedBlock.Transactions()) != len(block.Transactions()) {
		t.Errorf("Mismatch in transactions count, got: %v, want: %v", len(decodedBlock.Transactions()), len(block.Transactions()))
	}

	// body := &Body{block.transactions}
	// fmt.Printf("body: %+v\n", body)

	// data, err := rlp.EncodeToBytes(body)
	// assert.Nil(t, err)
	// fmt.Printf("data: %+v\n", data)

	// decodedBody := rlp.DecodeBytes(data, &body)
	// fmt.Printf("decodedBody: %+v\n", decodedBody)

	// decodedBody := decodedBlock.Body()

}

func randomBlock(t *testing.T, height int64, prevBlockhash common.Hash, key cryptoocax.PrivateKey) *Block {
	pubKey := key.PublicKey()

	tx1 := randomTxWithSignature(t, key)
	tx2 := randomTxWithSignature(t, key)

	txs := []*Transaction{tx1, tx2}

	header := &Header{
		Version:    1,
		ParentHash: prevBlockhash,
		Timestamp:  uint64(time.Now().UnixNano()),
		Height:     big.NewInt(height),
	}

	b := NewBlock(header, txs, pubKey)
	assert.Nil(t, b.Sign(key))

	return b
}
