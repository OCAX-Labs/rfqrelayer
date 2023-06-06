package types

import "github.com/OCAX-labs/rfqrelayer/common"

type TxEvent struct {
	TxType      uint8
	TxHash      common.Hash
	Transaction interface{} // Can be RFQRequest, Quote, or other types as needed
}

// used to allow listeners to be registered for events
type OpenRFQCallback func(*OpenRFQ)
