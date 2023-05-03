package network

import (
	"bytes"
	"crypto/elliptic"
	"encoding/gob"
	"fmt"
	"io"
	"net"

	"github.com/OCAX-labs/rfqrelayer/core"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	"github.com/sirupsen/logrus"
)

type MessageType byte

const (
	MessageTypeTx        MessageType = 0x1
	MessageTypeBlock     MessageType = 0x2
	MessageTypeGetBlocks MessageType = 0x3
	MessageTypeStatus    MessageType = 0x4
	MessageTypeGetStatus MessageType = 0x5
	MessageTypeBlocks    MessageType = 0x6
)

type RPC struct {
	From    net.Addr
	Payload io.Reader
}

type Message struct {
	Header MessageType
	Data   []byte
	ID     string
}

func NewMessage(t MessageType, data []byte, id string) *Message {
	return &Message{
		Header: t,
		Data:   data,
		ID:     id,
	}
}

func (msg *Message) Bytes() []byte {
	buf := &bytes.Buffer{}
	gob.NewEncoder(buf).Encode(msg)
	return buf.Bytes()
}

type DecodeMessage struct {
	ID   string
	From net.Addr
	Data any
}

type RPCDecodeFunc func(RPC) (*DecodeMessage, error)

func DefaultRPCDecodeFunc(rpc RPC) (*DecodeMessage, error) {
	msg := Message{}
	if err := gob.NewDecoder(rpc.Payload).Decode(&msg); err != nil {
		return nil, fmt.Errorf("failed to decode message from %s: %s", rpc.From, err)
	}

	logrus.WithFields(logrus.Fields{
		"ID":   msg.ID,
		"from": rpc.From,
		"type": msg.Header,
	}).Debug(fmt.Sprintf("received message with header %+v", msg.Header))

	switch msg.Header {
	case MessageTypeTx:
		tx := new(types.Transaction)
		// if err := tx.Decode(core.NewRLPTxDecoder(bytes.NewReader(msg.Data))); err != nil {
		// 	return nil, err
		// }

		return &DecodeMessage{
			ID:   msg.ID,
			From: rpc.From,
			Data: tx,
		}, nil

	case MessageTypeBlock:
		block := new(types.Block)
		if err := block.Decode(core.NewRLPBlockDecoder(bytes.NewReader(msg.Data))); err != nil {
			return nil, err
		}

		return &DecodeMessage{
			ID:   msg.ID,
			From: rpc.From,
			Data: block,
		}, nil

	case MessageTypeGetStatus:
		return &DecodeMessage{
			ID:   msg.ID,
			From: rpc.From,
			Data: &GetStatusMessage{ID: msg.ID},
		}, nil

	case MessageTypeStatus:
		statusMessage := new(StatusMessage)
		if err := gob.NewDecoder(bytes.NewReader(msg.Data)).Decode(statusMessage); err != nil {
			return nil, err
		}

		return &DecodeMessage{
			ID:   msg.ID,
			From: rpc.From,
			Data: statusMessage,
		}, nil

	case MessageTypeGetBlocks:
		getBlocks := new(GetBlocksMessage)
		if err := gob.NewDecoder(bytes.NewReader(msg.Data)).Decode(getBlocks); err != nil {
			return nil, err
		}

		return &DecodeMessage{
			ID:   msg.ID,
			From: rpc.From,
			Data: getBlocks,
		}, nil

	case MessageTypeBlocks:
		blocks := new(BlocksMessage)
		if err := gob.NewDecoder(bytes.NewReader(msg.Data)).Decode(blocks); err != nil {
			return nil, err
		}

		return &DecodeMessage{
			ID:   msg.ID,
			From: rpc.From,
			Data: blocks,
		}, nil

	default:
		return nil, fmt.Errorf("unknown message header type: %x", msg.Header)
	}
}

type RPCProcessor interface {
	ProcessMessage(*DecodeMessage) error
}

func init() {
	gob.Register(elliptic.P256())
}
