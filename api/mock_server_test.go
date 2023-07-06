package api

import (
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core/types"
)

type MockChain struct{}

func (mc *MockChain) GetTxByHash(hash common.Hash) (*types.Transaction, error) {
	// Return a fake Transaction and no error
	return &types.Transaction{}, nil
}

func (mc *MockChain) GetBlockByHash(hash common.Hash) (*types.Block, error) {
	// Return a fake Block and no error
	return &types.Block{}, nil
}

func (mc *MockChain) GetBlock(height *big.Int) (*types.Block, error) {
	// Return a fake Block and no error
	return &types.Block{}, nil
}

func (mc *MockChain) GetBlockHeader(height *big.Int) (*types.Header, error) {
	// Return a fake Header and no error
	return &types.Header{}, nil
}

func (mc *MockChain) GetRFQRequests() ([]*types.RFQRequest, error) {
	// Return a fake slice of RFQRequest pointers and no error
	return []*types.RFQRequest{}, nil
}

func (mc *MockChain) GetOpenRFQRequests() ([]*types.OpenRFQ, error) {
	// Return a fake slice of OpenRFQ pointers and no error
	return []*types.OpenRFQ{}, nil
}

func (mc *MockChain) WriteRFQTxs(tx *types.Transaction) error {
	// Return no error
	return nil
}

func (mc *MockChain) GetOpenRFQByHash(hash common.Hash) (*types.OpenRFQ, error) {
	// Return a fake OpenRFQ and no error
	return &types.OpenRFQ{}, nil
}

func (mc *MockChain) UpdateActiveRFQ(rfqTxHash common.Hash, quote *types.Quote) error {
	// Return no error
	return nil
}
