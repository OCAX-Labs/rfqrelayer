package network

import "github.com/OCAX-labs/rfqrelayer/core/types"

type GetBlocksMessage struct {
	ID   string
	From uint64

	// To = 0 max blocks returned
	To uint64
}

type BlocksMessage struct {
	ID     string
	Blocks []*FullBlock
}

type GetStatusMessage struct {
	ID string
}

type StatusMessage struct {
	ID            string
	Version       uint32
	CurrentLength int64
}

type FullBlock struct {
	Block  *types.Block
	Header *types.Header
}
