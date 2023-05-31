package core

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core/rawdb"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/OCAX-labs/rfqrelayer/db/pebble"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
)

const dbPath = "../.testdb"

const (
	devDb    = "./.devdb"
	cache    = 1048
	handles  = 2
	readonly = false
)

var testKey = cryptoocax.GeneratePrivateKey()

func TestAddBlock(t *testing.T) {
	bc, teardown := newBlockchainWithGenesis(t, dbPath+"addblock")
	defer teardown()
	lenBlocks := 10
	for i := 0; i < lenBlocks; i++ {
		prevBlHash := getPrevBlockHash(t, bc, big.NewInt(int64(i)))
		block := randomBlockWithSignature(t, testKey, uint64(i+1), prevBlHash)
		assert.Nil(t, bc.VerifyBlock(block))
	}

	assert.Equal(t, uint64(10), bc.Height().Uint64())
	// assert.Equal(t, bc.blocks[100], bc.Height())
	assert.Equal(t, 11, len(bc.headers))
	assert.Equal(t, bc.headers[0].Height.Uint64(), uint64(0))

	assert.NotNil(t, bc.VerifyBlock(randomBlock(t, 89, common.Hash{})))
	// Check that the database can retrieve the last block
}

func TestNewBlockchain(t *testing.T) {
	// Delete the database directory if it exists
	cleanDb(t, dbPath+"newblockchain")
	bc, teardown := newBlockchainWithGenesis(t, dbPath+"newblockchain")
	defer teardown()
	lenBlocks := 2
	for i := 0; i < lenBlocks; i++ {
		prevBlHash := getPrevBlockHash(t, bc, big.NewInt(int64(i)))
		block := randomBlockWithSignature(t, testKey, uint64(i+1), prevBlHash)
		assert.Nil(t, bc.VerifyBlock(block))
	}
	// bc := newBlockchainWithGenesis(t, dbPath)

	assert.NotNil(t, bc.validator)
	assert.Equal(t, big.NewInt(2), bc.Height())
	// size, err := bc.db.Size()
	// assert.Nil(t, err)
	// assert.Equal(t, int64(3), size)

	hash := bc.headers[0].Hash()
	body := rawdb.HasBody(bc.db, hash, bc.headers[0].Height.Uint64())
	assert.True(t, body)
	genesis := rawdb.ReadBlock(bc.db, hash, bc.headers[0].Height.Uint64())
	assert.NotNil(t, genesis)
	assert.Equal(t, genesis.Header(), bc.headers[0])
	assert.Equal(t, len(bc.headers), 3)
	second := rawdb.ReadBlock(bc.db, bc.headers[1].Hash(), bc.headers[1].Height.Uint64())
	assert.NotNil(t, second)
	assert.Equal(t, second.Header(), bc.headers[1])
	assert.Equal(t, genesis.Header().Hash(), bc.headers[1].ParentHash)
	assert.Equal(t, testKey.PublicKey(), genesis.Validator)

	// assert.Equal(t, genesis.Header(), block.Header)
}

func TestEncodings(t *testing.T) {
	tx := randomTxWithSignature(t, testKey)

	var buf bytes.Buffer
	err := tx.EncodeRLP(&buf)
	assert.Nil(t, err)
	// assert.Equal(t, uint8(0))
	var decodedTx types.Transaction
	s := rlp.NewStream(&buf, 0)
	err = decodedTx.DecodeRLP(s)
	// err = rlp.Decode(&buffer, &decodedReq)
	if err != nil {
		t.Fatalf("Failed to decode Body: %v", err)
	}

	transactionsEqual(t, tx, &decodedTx)

}

func transactionsEqual(t *testing.T, expected, actual *types.Transaction) {
	t.Helper()

	// Compare the fields that matter.
	if expected.From().String() != actual.From().String() {
		t.Errorf("Transaction.From: expected %v, got %v", expected.From(), actual.From())
	}
	if !bytes.Equal(expected.Data(), actual.Data()) {
		t.Errorf("Transaction.Data: expected %v, got %v", expected.Data(), actual.Data())
	}
	if expected.Type() != actual.Type() {
		t.Errorf("Transaction.TxType: expected %v, got %v", expected.Type(), actual.Type())
	}

	ev, er, es := expected.RawSignatureValues()
	av, ar, as := actual.RawSignatureValues()

	if ev != nil && av != nil && ev.Cmp(av) != 0 {
		t.Errorf("Transaction.RawSignatureValues (V): expected %v, got %v", ev, av)
	}

	if er != nil && ar != nil && er.Cmp(ar) != 0 {
		t.Errorf("Transaction.RawSignatureValues (R): expected %v, got %v", er, ar)
	}

	if es != nil && as != nil && es.Cmp(as) != 0 {
		t.Errorf("Transaction.RawSignatureValues (S): expected %v, got %v", es, as)
	}
}

func TestHasBlock(t *testing.T) {
	// Delete the database directory if it exists

	bc, teardown := newBlockchainWithGenesis(t, dbPath+"hasblock")
	defer teardown()

	assert.True(t, bc.HasBlock(big.NewInt(0)))
	assert.False(t, bc.HasBlock(big.NewInt(1)))
	assert.False(t, bc.HasBlock(big.NewInt(100)))
	_, err := bc.GetBlock(big.NewInt(0))
	assert.Nil(t, err)
}

func TestGetBlock(t *testing.T) {

	bc, teardown := newBlockchainWithGenesis(t, dbPath+"getblock")
	defer teardown()
	assert.Equal(t, big.NewInt(0), bc.Height())
	assert.Equal(t, bc.headers[0].Height.Uint64(), uint64(0))
	b, err := bc.GetBlock(big.NewInt(0))
	assert.Nil(t, err)
	assert.NotNil(t, b)

	lenBlocks := 1

	for i := 0; i < lenBlocks; i++ {
		prevBlockHash := getPrevBlockHash(t, bc, big.NewInt(int64(i)))
		block := randomBlockWithSignature(t, testKey, uint64(i+1), prevBlockHash)
		assert.Nil(t, bc.VerifyBlock(block))
	}

	lastHeight := bc.Height()
	lastBlock, err := bc.GetBlock(lastHeight)
	assert.Nil(t, err)
	assert.NotNil(t, lastBlock)
	assert.Equal(t, bc.headers[int(lastHeight.Uint64())], lastBlock.Header())
	assert.Equal(t, lastHeight, big.NewInt(1))
	assert.Equal(t, lastBlock.Header().Hash(), bc.headers[1].Hash())
	assert.Equal(t, lastBlock.Header().ParentHash, bc.headers[0].Hash())
	assert.Equal(t, lastBlock.Validator, testKey.PublicKey())
}

func TestGetHeader(t *testing.T) {
	// Delete the database directory if it exists
	bc, teardown := newBlockchainWithGenesis(t, dbPath+"getheader")
	defer teardown()
	lenBlocks := 3

	for i := 0; i < lenBlocks; i++ {
		prevHash := getPrevBlockHash(t, bc, big.NewInt(int64(i)))
		block := randomBlockWithSignature(t, testKey, uint64(i+1), prevHash)
		assert.Nil(t, bc.VerifyBlock(block))
		header, err := bc.GetHeader(bc.Height())
		assert.Nil(t, err)
		assert.Equal(t, header, bc.headers[bc.Height().Int64()])

	}

}

func TestAddBlockToHigh(t *testing.T) {
	bc, teardown := newBlockchainWithGenesis(t, dbPath+"addblocktohigh")
	defer teardown()

	assert.Nil(t, bc.VerifyBlock(randomBlockWithSignature(t, testKey, 1, getPrevBlockHash(t, bc, big.NewInt(int64(0))))))
	assert.NotNil(t, bc.VerifyBlock(randomBlockWithSignature(t, testKey, 3, common.Hash{})))
}

func newBlockchainWithGenesis(t *testing.T, dbPath string) (*Blockchain, func()) {
	// Create the database
	cleanDb(t, dbPath)
	db, teardown := setupDB(t, dbPath)
	defer teardown()
	bc, err := NewBlockchain(log.NewNopLogger(), randomBlockWithSignature(t, testKey, 0, common.Hash{}), db, true)
	assert.Nil(t, err)
	return bc, teardown
}

func getPrevBlockHash(t *testing.T, bc *Blockchain, height *big.Int) common.Hash {
	prevIndex := height.Int64()
	prevHeader, err := bc.GetHeader(big.NewInt(prevIndex))
	assert.Nil(t, err)
	return prevHeader.Hash()
}

func cleanDb(t *testing.T, dbPath string) {
	err := deleteDirectoryIfExists(dbPath)
	assert.Nil(t, err)
}

func deleteDirectoryIfExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.RemoveAll(path)
}

func RandomBytes(size int) []byte {
	token := make([]byte, size)
	rand.Read(token)
	return token
}

func RandomHash() common.Hash {
	return common.HashFromBytes(RandomBytes(32))
}

// NewRandomTransaction return a new random transaction without signature.
func randomTx(pubKey cryptoocax.PublicKey) *types.Transaction {
	from := pubKey.Address()
	// rand, err := rand.Int(rand.Reader, big.NewInt(100000000))
	// rand, err := rand.Int(rand.Reader, big.NewInt(100000000))	// if err != nil {
	// 	panic(err)
	// }
	data := types.SignableRFQData{}

	inner := &types.RFQRequest{
		From: from,
		Data: data,
	}

	tx := types.NewTx(inner)

	return tx
}

func randomTxWithSignature(t *testing.T, privKey cryptoocax.PrivateKey) *types.Transaction {
	pubKey := privKey.PublicKey()
	tx := randomTx(pubKey)
	signedTx, err := tx.Sign(privKey)
	r, s, _ := signedTx.RawSignatureValues()
	assert.NotNil(t, r)
	assert.NotNil(t, s)
	assert.Nil(t, err)
	return signedTx
}

func randomBlock(t *testing.T, height uint64, prevHash common.Hash) *types.Block {
	txSigner := cryptoocax.GeneratePrivateKey()
	tx1 := randomTxWithSignature(t, txSigner)
	tx2 := randomTxWithSignature(t, txSigner)
	txs := types.Transactions{tx1, tx2}
	// fmt.Printf("txs: %+v\n", txs)
	// fmt.Printf("txs[0]: %+v txs[1]: %+v\n", txs[0], txs[1])
	blHeight := big.NewInt(int64(height))
	header := &types.Header{
		Version:    1,
		ParentHash: prevHash,
		Height:     blHeight,
		Timestamp:  uint64(time.Now().UnixNano()),
	}
	b := types.NewBlock(header, txs, testKey.PublicKey())

	return b
}

func randomBlockWithSignature(t *testing.T, pk cryptoocax.PrivateKey, height uint64, prevHash common.Hash) *types.Block {
	b := randomBlock(t, height, prevHash)
	assert.Nil(t, b.Sign(pk))
	b.Validator = pk.PublicKey()
	return b
}

func removeTestDB() {
	// Get a list of all files in the current directoryA
	matches, err := filepath.Glob(filepath.Join("../", ".testdb*"))
	if err != nil {
		panic(err)
	}

	// Iterate over each file that matches the pattern
	for _, file := range matches {
		// Remove the file or directory (os.RemoveAll behaves like `rm -rf`)
		err = os.RemoveAll(file)
		if err != nil {
			panic(err)
		}
	}
}

func setupDB(t *testing.T, dbPath string) (db *pebble.Database, teardown func()) {
	// Create the database
	cleanDb(t, dbPath)

	db, err := pebble.New(dbPath, cache, handles, "rfq", readonly)
	if err != nil {
		t.Fatal(err)
	}
	// Return the database and the teardown function
	return db, func() {
		// Close the database first
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		// Then remove the database files
		removeTestDB()
	}
}
