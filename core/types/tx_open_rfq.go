package types

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/ethereum/go-ethereum/rlp"
)

type RFQStatus string

const (
	RFQStatusOpen    RFQStatus = "OPEN"
	RFQStatusClosed  RFQStatus = "CLOSED"
	RFQStatusMatched RFQStatus = "MATCHED"
	RFQStatusSettled RFQStatus = "SETTLED"
)

type RFQData struct {
	RFQTxHash          common.Hash    `json:"rfqTxHash"`
	RFQRequest         *SignableData  `json:"rfqRequest"`
	RFQStartTime       int64          `json:"rfqStartTime"` // this will hold a Unix timestamp
	RFQEndTime         int64          `json:"rfqEndTime"`
	Quotes             []*Quote       `json:"quotes"`
	SettlementContract common.Address `json:"settlementContract"`
	MatchingContract   common.Address `json:"matchingContract"`
	Status             RFQStatus      `json:"status"`
}

func (d RFQData) String() string {
	return fmt.Sprintf(
		`RFQData{
    RFQTxHash: %s, 
    RfqRequest: %s, 
    RFQStartTime: %d, 
    RFQEndTime: %d, 
    SettlementContract: %s, 
    MatchingContract: %s
	Status: %s}`,
		d.RFQTxHash.Hex(),
		d.RFQRequest.String(),
		d.RFQStartTime,
		d.RFQEndTime,
		d.SettlementContract.Hex(),
		d.MatchingContract.Hex(),
		d.Status,
	)
}

func (d *RFQData) Close() {
	d.Status = RFQStatusClosed
}
func (d *RFQData) Matched() {
	d.Status = RFQStatusMatched
}

func (d *RFQData) Settled() {
	d.Status = RFQStatusSettled
}

type OpenRFQ struct {
	From common.Address `json:"from" gencodec:"required"`
	Data *RFQData       `json:"data" gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}

func NewOpenRFQ(from common.Address, data *RFQData) *OpenRFQ {
	return &OpenRFQ{
		Data: data,
		From: from,
	}
}

func (tx *OpenRFQ) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		From common.Address `json:"from"`
		Data *RFQData       `json:"data"`
		V    *big.Int       `json:"v"`
		R    *big.Int       `json:"r"`
		S    *big.Int       `json:"s"`
	}{
		From: tx.From,
		Data: tx.Data,
		V:    tx.V,
		R:    tx.R,
		S:    tx.S,
	})
}

func (tx *RFQData) JSON() ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(tx)
	return buffer.Bytes(), err
}

func (tx *OpenRFQ) UnmarshalJSON(input []byte) error {
	type OpenRFQJSON struct {
		From common.Address `json:"from"`
		Data *RFQData       `json:"data"`
		V    *big.Int       `json:"v"`
		R    *big.Int       `json:"r"`
		S    *big.Int       `json:"s"`
	}

	var txJSON OpenRFQJSON
	if err := json.Unmarshal(input, &txJSON); err != nil {
		return err
	}

	tx.From = txJSON.From
	tx.Data = txJSON.Data
	tx.V = txJSON.V
	tx.R = txJSON.R
	tx.S = txJSON.S

	return nil
}

func (tx *OpenRFQ) AddSignatureToTx(sig []byte) error {
	if len(sig) != 65 {
		return errors.New("invalid signature length")
	}
	tx.V = new(big.Int).SetBytes(sig[64:])
	tx.R = new(big.Int).SetBytes(sig[:32])
	tx.S = new(big.Int).SetBytes(sig[32:64])
	return nil
}

func (tx *OpenRFQ) copy() TxData {
	cpy := &OpenRFQ{
		From: common.Address(common.CopyBytes(tx.From.Bytes())),
		// These are initialized below.
		V: new(big.Int),
		R: new(big.Int),
		S: new(big.Int),
	}

	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}

	// Deep copy the data.
	dataFields, err := tx.Data.deepCopy()
	if err != nil {
		log.Printf("Error in function %s: %s", "someFunc", err)
		panic(fmt.Sprintf("failed to deep copy tx data: %v", err))
	}

	cpy.Data = dataFields

	return cpy
}

func (tx *OpenRFQ) from() *common.Address { return &tx.From }
func (tx *OpenRFQ) txType() byte          { return OpenRFQTxType }

func (tx *OpenRFQ) data() []byte {
	txDataBytes, err := tx.Data.ToBytes()
	if err != nil {
		panic(fmt.Sprintf("failed to marshal tx data: %v", err))
	}
	return txDataBytes
}

func (tx *OpenRFQ) openRFQData() *RFQData {
	return tx.Data
}

func (tx *OpenRFQ) embeddedData() interface{} {
	return tx.openRFQData()
}

func (r *RFQData) ToBytes() ([]byte, error) {
	buffer := &bytes.Buffer{}
	if err := rlp.Encode(buffer, r); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// the hash of the underlying RFQRquest transaction that led to this OpenRFQ
func (tx *OpenRFQ) referenceTxHash() common.Hash {
	return tx.Data.RFQTxHash
}

func (tx *OpenRFQ) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}
func (tx *OpenRFQ) setSignatureValues(v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}

func (r *OpenRFQ) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{r.From.Bytes(), r.Data, r.V, r.R, r.S})
}

func (r *OpenRFQ) DecodeRLP(s *rlp.Stream) error {
	raw, err := s.Raw()
	if err != nil {
		return err
	}

	var elems []interface{}
	if err := rlp.DecodeBytes(raw, &elems); err != nil {
		return err
	}

	if len(elems) != 5 {
		return fmt.Errorf("expected 5 elements, got %d", len(elems))
	}

	from, ok := elems[0].([]byte)
	if !ok {
		return fmt.Errorf("invalid type for From")
	}

	if len(from) != common.AddressLength {
		return fmt.Errorf("incorrect length for From, expected %d, got %d", common.AddressLength, len(from))
	}

	var addr common.Address
	copy(addr[:], from)

	data := &RFQData{}
	if err := data.FromInterfaces(elems[1].([]interface{})); err != nil {
		return fmt.Errorf("invalid type for Data: %w", err)
	}

	vBytes, ok := elems[2].([]byte)
	if !ok {
		return fmt.Errorf("invalid type for V")
	}
	v := new(big.Int).SetBytes(vBytes)

	rBytes, ok := elems[3].([]byte)
	if !ok {
		return fmt.Errorf("invalid type for R")
	}

	sBytes, ok := elems[4].([]byte)
	if !ok {
		return fmt.Errorf("invalid type for S")
	}

	r.From = addr
	r.Data = data
	r.V = v
	r.R = new(big.Int).SetBytes(rBytes)
	r.S = new(big.Int).SetBytes(sBytes)

	return nil
}

func (rfqData *RFQData) FromInterfaces(data []interface{}) error {
	if len(data) != 8 {
		return fmt.Errorf("wrong number of elements: expected 7, got %d", len(data))
	}

	rfqTxHashBytes, ok := data[0].([]byte)
	if !ok {
		return errors.New("data[0] is not a byte array")
	}

	if len(rfqTxHashBytes) != common.HashLength {
		return fmt.Errorf("incorrect length for rfqTxHash, expected %d, got %d", common.HashLength, len(rfqTxHashBytes))
	}

	var rfqTxHash common.Hash
	copy(rfqTxHash[:], rfqTxHashBytes)

	rfqRequestData, ok := data[1].([]interface{})
	if !ok {
		return errors.New("data[1] is not a []interface{}")
	}

	rfqRequest := &SignableData{}
	err := rfqRequest.FromInterfaces(rfqRequestData)
	if err != nil {
		return fmt.Errorf("error decoding SignableData: %s", err.Error())
	}

	// Handle rfqStartTime as []byte
	rfqStartTimeBytes, ok := data[2].([]byte)
	if !ok {
		return fmt.Errorf("invalid rfqStartTime type %T", data[2])
	}

	if len(rfqStartTimeBytes) > 8 {
		return errors.New("invalid rfqStartTime length")
	}

	// Create a new byte slice of length 8
	newRfqStartTimeBytes := make([]byte, 8)

	// Copy rfqStartTimeBytes to the end of newRfqStartTimeBytes
	copy(newRfqStartTimeBytes[8-len(rfqStartTimeBytes):], rfqStartTimeBytes)

	// Convert the bytes to uint64
	rfqStartTime := binary.BigEndian.Uint64(newRfqStartTimeBytes)

	// Handle rfqStartTime as []byte
	rfqEndTimeBytes, ok := data[3].([]byte)
	if !ok {
		return fmt.Errorf("invalid rfqEndTime type %T", data[3])
	}

	if len(rfqEndTimeBytes) > 8 {
		return errors.New("invalid rfqEndTime length")
	}

	// Create a new byte slice of length 8
	newRfqEndTimeBytes := make([]byte, 8)

	// Copy rfqStartTimeBytes to the end of newRfqStartTimeBytes
	copy(newRfqEndTimeBytes[8-len(rfqEndTimeBytes):], rfqEndTimeBytes)

	// Convert the bytes to uint64
	rfqEndTime := binary.BigEndian.Uint64(newRfqEndTimeBytes)

	quoteInterfaces, ok := data[4].([]interface{})
	if !ok {
		return fmt.Errorf("invalid quotes type %T", data[4])
	}

	var quotes []*Quote

	for _, quoteInterface := range quoteInterfaces {
		quoteData, ok := quoteInterface.([]interface{})
		if !ok {
			return fmt.Errorf("invalid quote type %T", quoteInterface)
		}

		quote := &Quote{}
		err := quote.FromInterfaces(quoteData)
		if err != nil {
			return fmt.Errorf("error decoding Quote: %s", err.Error())
		}

		quotes = append(quotes, quote)
	}

	settlementContractAddressBytes, ok := data[5].([]byte)
	if !ok {
		return fmt.Errorf("invalid address type %T", data[5])
	}
	settlementContractAddress := common.BytesToAddress(settlementContractAddressBytes)

	matchingContractAddressBytes, ok := data[6].([]byte)
	if !ok {
		return fmt.Errorf("invalid address type %T", data[6])
	}
	matchingContractAddress := common.BytesToAddress(matchingContractAddressBytes)

	statusBytes, ok := data[7].([]byte) // the 8th element will be the status
	if !ok {
		return fmt.Errorf("invalid status type %T", data[7])
	}
	status := string(statusBytes) // convert bytes to string
	rfqData.RFQTxHash = rfqTxHash
	rfqData.RFQRequest = rfqRequest
	rfqData.RFQStartTime = int64(rfqStartTime)
	rfqData.RFQEndTime = int64(rfqEndTime)
	rfqData.Quotes = quotes
	rfqData.SettlementContract = settlementContractAddress
	rfqData.MatchingContract = matchingContractAddress
	rfqData.Status = RFQStatus(status)

	return nil
}

func (tx *OpenRFQ) DataString() string {
	dataBytes, err := json.MarshalIndent(tx.Data, "", "  ")
	if err != nil {
		// handle error here or return an error string
		return "error in marshaling data"
	}
	return string(dataBytes)
}

func (tx *OpenRFQ) String() string {
	return fmt.Sprintf("OpenRFQ{From: %s, Data: %s, V: %s, R: %s, S: %s}",
		tx.From.Hex(),
		tx.DataString(),
		tx.V.String(),
		tx.R.String(),
		tx.S.String())
}

func (src *RFQData) Validate() error {
	// add validation logic here
	return nil
}

func (src *RFQData) EncodeRLP(w io.Writer) error {
	byteStartTime := make([]byte, 8)
	binary.BigEndian.PutUint64(byteStartTime, uint64(src.RFQStartTime))
	byteEndTime := make([]byte, 8)
	binary.BigEndian.PutUint64(byteEndTime, uint64(src.RFQEndTime))

	dataToEncode := struct {
		RFQTxHash          common.Hash
		RFQRequest         *SignableData
		RFQStartTime       []byte
		RFQEndTime         []byte
		Quotes             []*Quote
		SettlementContract common.Address
		MatchingContract   common.Address
		Status             RFQStatus
	}{
		RFQTxHash:          src.RFQTxHash,
		RFQRequest:         src.RFQRequest,
		RFQStartTime:       byteStartTime,
		RFQEndTime:         byteEndTime,
		Quotes:             src.Quotes,
		SettlementContract: src.SettlementContract,
		MatchingContract:   src.MatchingContract,
		Status:             src.Status,
	}
	return rlp.Encode(w, &dataToEncode)
}

func (src *RFQData) DecodeRLP(s *rlp.Stream) error {
	var dataToDecode struct {
		RFQTxHash          common.Hash
		RFQRequest         *SignableData
		RFQStartTime       []byte
		RFQEndTime         []byte
		Quotes             []*Quote
		SettlementContract common.Address
		MatchingContract   common.Address
		Status             RFQStatus
	}

	if err := s.Decode(&dataToDecode); err != nil {
		return err
	}

	src.RFQTxHash = dataToDecode.RFQTxHash
	src.RFQRequest = dataToDecode.RFQRequest
	src.RFQStartTime = int64(binary.BigEndian.Uint64(dataToDecode.RFQStartTime))
	src.RFQEndTime = int64(binary.BigEndian.Uint64(dataToDecode.RFQEndTime))
	src.Quotes = dataToDecode.Quotes
	src.SettlementContract = dataToDecode.SettlementContract
	src.MatchingContract = dataToDecode.MatchingContract
	src.Status = dataToDecode.Status
	return nil
}

func (src *RFQData) deepCopy() (*RFQData, error) {
	cpy := &RFQData{
		RFQTxHash:          src.RFQTxHash,  // Hash is a value type
		RFQRequest:         src.RFQRequest, // Assuming SignableData can be safely shallow-copied.
		RFQStartTime:       src.RFQStartTime,
		RFQEndTime:         src.RFQEndTime,
		SettlementContract: src.SettlementContract, // Address is a value type
		MatchingContract:   src.MatchingContract,
		Status:             src.Status, // Address is a value type
	}

	// Deep copy the slices// Deep copy the slices
	cpy.Quotes = make([]*Quote, len(src.Quotes))
	copy(cpy.Quotes, src.Quotes)
	return cpy, nil
}
