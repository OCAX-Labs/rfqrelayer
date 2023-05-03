package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/core/types"
)

var (
	ErrBlockKnown   = errors.New("block already known")
	ErrBlockInvalid = errors.New("block is invalid")
)

type Validator interface {
	ValidateBlock(b *types.Block) error
}

type BlockValidator struct {
	bc *Blockchain
}

func NewBlockValidator(bc *Blockchain) *BlockValidator {
	return &BlockValidator{
		bc: bc,
	}
}

func (v *BlockValidator) ValidateBlock(b *types.Block) error {
	// validate block header
	// validate block transactions
	// validate block hash
	var proposedBlockHeight *big.Int
	if b != nil {
		proposedBlockHeight = b.Height()
	} else {
		return ErrBlockInvalid
	}

	if v.bc.HasBlock(proposedBlockHeight) {
		// return fmt.Errorf("block [%d] already exists with hash [%x]", b.Height, b.Hash(BlockHasher{}))
		return ErrBlockKnown
	}

	// is the height  higher than next ValidateBlock
	currHeight := v.bc.Height()
	nextHeight := currHeight.Add(currHeight, big.NewInt(1))
	// now need to add 1 to a big int currHeight

	if proposedBlockHeight.Cmp(nextHeight) != 0 {
		return fmt.Errorf("proposed block height [%d] is too high - current height [%d] - block %s", proposedBlockHeight, nextHeight, b.Hash())
	}

	prevHeight := proposedBlockHeight.Sub(proposedBlockHeight, big.NewInt(1))

	prevHeader, err := v.bc.GetHeader(prevHeight)
	if err != nil {
		return err
	}

	hash := prevHeader.Hash()
	if hash != b.ParentHash() {
		return fmt.Errorf("block prev hash [%x] does not match prev header hash [%x]", b.ParentHash(), hash)
	}

	if err := b.Verify(); err != nil {
		return err
	}

	return nil
}
