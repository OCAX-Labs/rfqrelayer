package rawdb

// import (
// 	"math/big"
// 	"reflect"
// 	"testing"

// 	"github.com/OCAX-labs/rfqrelayer/common"
// )

// func hashString(s string) common.Hash {
// 	return types.RlpHash(s)
// }
// func TestBlockReadWrite(t *testing.T) {
// 	db := NewMockStore()

// 	header := &types.Header{
// 		Version:    1,
// 		TxHash:     types.RlpHash([]byte("txhash")),
// 		ParentHash: types.RlpHash([]byte("parent")),
// 		Timestamp:  123456,
// 		Height:     big.NewInt(1),
// 	}

// 	privateKey := cryptoocax.GeneratePrivateKey()

// 	hasher := types.NewOcaxHasher()
// 	block := types.NewBlock(header, types.Transactions{}, privateKey.PublicKey(), hasher)

// 	err := WriteBlock(db, block)
// 	if err != nil {
// 		t.Fatalf("WriteBlock failed: %v", err)
// 	}

// 	readBlock, err := ReadBlock(db, block.Hash())
// 	if err != nil {
// 		t.Fatalf("ReadBlock failed: %v", err)
// 	}

// 	if !reflect.DeepEqual(block, readBlock) {
// 		t.Fatalf("blocks do not match: got %+v, want %+v", readBlock, block)
// 	}
// }
