package network

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/OCAX-labs/rfqrelayer/api"
	"github.com/OCAX-labs/rfqrelayer/common"
	"github.com/OCAX-labs/rfqrelayer/core"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/OCAX-labs/rfqrelayer/rfqdb/pebble"
	"github.com/go-kit/log"
)

const (
	devDb    = "./.devdb"
	cache    = 1048
	handles  = 2
	readonly = false
)

var (
	defaultBlockTime = 5 * time.Second

	// Message coloring for Debug
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	Gray   = "\033[37m"
	White  = "\033[97m"
)

// Server is the main entry point into the node.

type ServerOptions struct {
	APIListenAddr string
	SeedNodes     []string
	ListenAddr    string
	TCPTransport  *TCPTransport
	ID            string
	Logger        log.Logger
	RPCDecodeFunc RPCDecodeFunc
	RPCProcessor  RPCProcessor
	BlockTime     time.Duration
	PrivateKey    *cryptoocax.PrivateKey
}

type Server struct {
	TCPTransport *TCPTransport
	peerCh       chan (*TCPPeer)

	mu      sync.RWMutex
	peerMap map[net.Addr]*TCPPeer
	txChan  chan *types.Transaction

	ServerOptions
	memPool     *TxPool
	chain       *core.Blockchain
	isValidator bool
	rpcCh       chan RPC
	quitCh      chan struct{} // options

	ctx        context.Context
	cancelFunc context.CancelFunc

	Callbacks []func(*types.OpenRFQ)
}

func NewServer(options ServerOptions) (*Server, error) {
	if options.BlockTime == 0 {
		options.BlockTime = defaultBlockTime
	}
	if options.RPCDecodeFunc == nil {
		options.RPCDecodeFunc = DefaultRPCDecodeFunc
	}
	if options.Logger == nil {
		options.Logger = log.NewLogfmtLogger(os.Stderr)
		options.Logger = log.With(options.Logger, "addr", options.ID)
	}
	log.Logger(options.Logger).Log("msg", "starting node", "id", options.ID)
	// Delete the database directory if it exists
	dbPath := fmt.Sprintf("./.%s.db", options.ID)
	err := deleteDirectoryIfExists(dbPath)
	if err != nil {
		panic(fmt.Sprintf("failed to delete test database directory: %v", err))
	}

	// Create the database
	db, err := pebble.New(dbPath, cache, handles, "rfq", readonly)
	if err != nil {
		return nil, err
	}

	chain, err := core.NewBlockchain(options.Logger, genesisBlock(), db, options.PrivateKey != nil)
	if err != nil {
		return nil, err
	}

	// channel used between json rpc api and the node server
	txChan := make(chan *types.Transaction)
	//
	var apiServer *api.Server
	if len(options.APIListenAddr) > 0 {
		apiServerCfg := api.ServerConfig{
			Logger:     options.Logger,
			ListenAddr: options.APIListenAddr,
		}

		apiServer = api.NewServer(apiServerCfg, chain, txChan)

		go apiServer.Start()

		options.Logger.Log("msg", "JSON API running", "addr", options.APIListenAddr)
	}

	peerCh := make(chan *TCPPeer)
	rpcCh := make(chan RPC, 2048)
	tr := NewTCPTransport(options.ID, options.ListenAddr, peerCh, rpcCh)

	ctx, cancelFunc := context.WithCancel(context.Background())

	s := &Server{
		TCPTransport:  tr,
		peerCh:        peerCh,
		peerMap:       make(map[net.Addr]*TCPPeer),
		ServerOptions: options,
		chain:         chain,
		memPool:       NewTxPool(1000),
		isValidator:   options.PrivateKey != nil,
		rpcCh:         rpcCh,
		quitCh:        make(chan struct{}, 1),
		txChan:        txChan,

		// for broadcasting status messages
		ctx:        ctx,
		cancelFunc: cancelFunc,
		Callbacks:  make([]func(*types.OpenRFQ), 0),
	}

	s.TCPTransport.peerCh = peerCh

	if s.RPCProcessor == nil {
		s.RPCProcessor = s
	}
	if s.isValidator {
		s.RegisterCallback(apiServer.BroadcastOpenRFQ)

		go func() {
			s.validatorLoop()
		}()
		go func() {
			time.Sleep(time.Second * 8)
			s.statusLoop()
		}()
	}
	return s, nil
}

func (s *Server) RegisterCallback(cb func(*types.OpenRFQ)) {
	s.Callbacks = append(s.Callbacks, cb)
}

func (s *Server) bootstrapNetwork() {
	for _, addr := range s.SeedNodes {

		go func(addr string) {

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				s.Logger.Log("err", err)
				return
			}
			peerCtx, cancel := context.WithCancel(context.Background()) // or pass in the server's context if it exists
			peer := &TCPPeer{
				conn:       conn,
				ctx:        peerCtx,
				cancelFunc: cancel,
			}

			s.peerCh <- peer

		}(addr)

	}
}

var ErrBlockKnown = errors.New("block already known")

func (s *Server) Start() {
	s.TCPTransport.Start()

	time.Sleep(time.Second * 2)

	s.bootstrapNetwork()

	s.Logger.Log("accepting tcp on", s.ListenAddr, "id", s.ID)
	var wg sync.WaitGroup

	if len(s.Callbacks) > 0 && s.isValidator {
		fmt.Printf("XXXX Starting callback loop\n")
		go s.listenToTxEvents()
	}

free:
	for {
		errors := make(chan error)
		select {
		case peer := <-s.peerCh:
			s.peerMap[peer.conn.RemoteAddr()] = peer
			peer.transport = s.TCPTransport

			s.Logger.Log("msg", "new peer added", "outgoing", peer.Outgoing, "addr", peer.conn.RemoteAddr())

			wg.Add(1)
			go func() {
				defer wg.Done()
				peer.readLoop(s.rpcCh, errors)
			}()
			go handleErrors(errors, s.Logger)

		case tx := <-s.txChan:
			fmt.Printf("XXXX Received tx [%+v]\n", tx)

			if err := s.processTransaction(tx); err != nil {
				s.Logger.Log("TX err", err)
			}

			// s.WriteToTables(tx)

			s.Logger.Log("msg", "new transaction received", "tx", tx)
		case rpc := <-s.rpcCh:
			msg, err := s.RPCDecodeFunc(rpc)
			fmt.Printf(Purple+"XXXX Received msg [%+v]"+Reset+"\n", msg.Data)
			if err != nil {
				s.Logger.Log("err", err)
				continue
			}
			if err := s.RPCProcessor.ProcessMessage(msg); err != nil {
				if err != ErrBlockKnown {
					s.Logger.Log("err", err)
				}
			}
		case <-s.quitCh:
			wg.Wait()
			close(errors)
			break free
		}
	}

	s.Logger.Log("msg", "server stopped")
}

func handleErrors(errors <-chan error, logger log.Logger) {
	for err := range errors {
		logger.Log("An error occurred in readloop", err)
	}
}

func (s *Server) listenToTxEvents() {
	go func() {
		for {
			select {
			case event := <-s.chain.EventChan:
				fmt.Printf("XXXX Received event [%+v]\n", event)
				s.handleTxEvent(event)
			}
		}
	}()
}

func (s *Server) handleTxEvent(event types.TxEvent) {
	switch event.TxType {
	case types.RFQRequestTxType:
		s.handleRFQRequest(event)
	case types.QuoteTxType:
		// ns.handleQuote(event)
		// Other transaction types...
	default:
		// Unknown or unsupported transaction type
		s.Logger.Log("msg", "Received unknown transaction type", "type", event.TxType)
	}
}

func (s *Server) handleRFQRequest(event types.TxEvent) {
	// To start a new RFQ process we broadcast to market makers the details of the RFQ
	// and the start and end times of the RFQ.
	// MMS will need to submit quotes before the RFQ end time.
	// This event is triggered when a new RFQRequest transaction is received on the chain.
	tx, ok := event.Transaction.(*types.Transaction)
	if !ok {
		s.Logger.Log("msg", "Failed to cast Transaction to Transaction", "hash", event.TxHash)
		return
	}

	// Create an OpenRFQ transaction and broadcast it to the network

	openRFQData := createOpenRFQData(tx, event.TxHash)
	currentTime := time.Now().Unix()
	openRFQData.RFQStartTime = currentTime
	openRFQData.RFQEndTime = currentTime + int64(tx.RFQData().RFQDurationMs)
	newOpenRfq := types.NewOpenRFQ(s.ServerOptions.PrivateKey.PublicKey().Address(), openRFQData)
	txOpenRfq := types.NewTx(newOpenRfq)
	signedTx, err := txOpenRfq.Sign(*s.ServerOptions.PrivateKey)
	if err != nil {
		s.Logger.Log("msg", "Failed to sign OpenRFQ", "err", err)
		return
	}

	// broadcast the new OpenRFQ over WebSockets
	for _, callback := range s.Callbacks {
		callback(newOpenRfq)
	}

	// We dont want rfqs to be constrained by block times so we also store the OpenRFQ to its own DB table
	// we store it with the key that represents the RFQRequest transaction hash that initiated the RFQ
	// and add it to our inmemory map of OpenRFQs
	// TODO: do we need to sync these tables that will only be available to validator nodes? Or do we just submit
	// final transactions to the blockchain and let the other nodes sync from there?

	s.chain.WriteRFQTxs(signedTx)

	// we add this to the servers list of open RFQs
	s.chain.AddOpenRFQTx(signedTx.ReferenceTxHash(), signedTx)

	// we submit it to the blockchain to provide a decentralized record of the RFQ Opening for bids
	s.txChan <- signedTx

}

func createOpenRFQData(rfq *types.Transaction, txHash common.Hash) *types.RFQData {
	fmt.Printf("Creating OpenRFQData %+v\n", rfq)
	return &types.RFQData{
		RFQTxHash:          txHash,
		RFQRequest:         rfq.RFQData(),
		RFQStartTime:       0,
		RFQEndTime:         0,
		SettlementContract: common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
		MatchingContract:   common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
	}
}

func (s *Server) validatorLoop() {
	ticker := time.NewTicker(s.BlockTime)

	s.Logger.Log("msg", "Starting validator loop", "blockTime", s.BlockTime)

	for {
		<-ticker.C
		s.CreateNewBlock()
	}
}

func (s *Server) ProcessMessage(msg *DecodeMessage) error {
	switch t := msg.Data.(type) {
	case *types.Transaction:
		fmt.Println("TX")
		return s.processTransaction(t)
	case *types.Block:
		return s.processBlock(t)
	case *GetStatusMessage:
		return s.processGetStatusMessage(msg.From, t)
	case *StatusMessage:
		return s.processStatusMessage(msg.From, t)
	case *GetBlocksMessage:
		fmt.Printf(Green+"GET BLOCKS MESSAGE - RECEIVED[%+v]: => from %+v t: %+v"+Reset+"\n", s.ID, msg.ID, t)
		return s.processGetBlocksMessage(msg.From, t)
	case *BlocksMessage:
		fmt.Printf(Yellow+"PROCESSBLOCKS MESSAGE - RECEIVED[%+v]: => from %+v t: %+v"+Reset+"\n", s.ID, msg.ID, t)
		return s.processBlocksMessage(msg.From, t)
	default:
		fmt.Printf(Yellow+"UNKNOWN MESSAGE TYPE: %+v"+Reset+"\n", t)

	}

	return nil
}

// GGG
func (s *Server) processGetBlocksMessage(from net.Addr, data *GetBlocksMessage) error {
	// s.Logger.Log("msg", "received GET BLOCKS msg", "from", from, "FromBlock", data.From, "ToBlock", data.To)

	var (
		fullBlocks       = []*FullBlock{}
		ourHeadersLength = uint64(len(s.chain.Headers()))
	)

	// Peovide all blocks up to our current height
	if data.From <= ourHeadersLength && data.To <= ourHeadersLength {
		for i := int(data.To); i <= int(data.From); i++ {
			block, err := s.chain.GetBlock(big.NewInt(int64(i)))
			if err != nil {
				return err
			}
			header := block.Header()
			fullBlocks = append(fullBlocks, &FullBlock{Block: block, Header: header})
		}
	}

	blocksMsg := &BlocksMessage{
		Blocks: fullBlocks,
	}

	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(blocksMsg); err != nil {
		return err
	}

	msg := NewMessage(MessageTypeBlocks, buf.Bytes(), s.ID)

	peer, ok := s.peerMap[from]
	if !ok {
		return fmt.Errorf("peer not found")
	}

	if err := peer.Send(msg); err != nil {
		return err
	}
	return nil
}

func (s *Server) broadcast(payload []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for netAddr, peer := range s.peerMap {
		if err := peer.SendBytesPayload(payload); err != nil {
			fmt.Printf("Error sending to peer: %+v\n", err)
			s.Logger.Log("err", err, "addr", netAddr)
		}

	}
	return nil
}

func (s *Server) processBlocksMessage(from net.Addr, data *BlocksMessage) error {
	fmt.Printf(Cyan+"processBlocksMessage: processing incoming msg: %+v"+Reset+"\n", data)
	for i := 0; i < len(data.Blocks); i++ {
		header := data.Blocks[i].Header
		block := data.Blocks[i].Block
		newBlock := types.NewBlockWithHeader(header).WithBody(block.Transactions(), block.Validator)

		if err := s.chain.VerifyBlock(newBlock); err != nil {
			s.Logger.Log("err", err)
			continue
		}

	}

	return nil
}

func (s *Server) processStatusMessage(from net.Addr, data *StatusMessage) error {
	// If I am not a validator I need block 0
	myHeadersLength := int64(len(s.chain.Headers()))
	if data.CurrentLength < myHeadersLength {
		s.Logger.Log("msg", "No sync: blockheight to low", "our headers len", myHeadersLength, "your headers len", data.CurrentLength, "addr", s.ID)
		return nil
	} // this remote has blocks we can sync}

	if !s.isValidator && myHeadersLength < data.CurrentLength {
		go s.requestBlocksLoop(from, data.CurrentLength)
	}
	return nil
}

func (s *Server) statusLoop() {
	ticker := time.NewTicker(defaultBlockTime)
	lastBroadcastHeight := s.chain.CurrentBlock().Height

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			currentHeight := s.chain.CurrentBlock().Height
			if currentHeight != lastBroadcastHeight {
				buf := new(bytes.Buffer)
				status := s.createStatusMessage(buf) // This should include the current block height
				for _, peer := range s.peerMap {
					_ = peer.Send(status)
				}
				lastBroadcastHeight = currentHeight
			}
		}
	}
}

func (s *Server) processGetStatusMessage(from net.Addr, data *GetStatusMessage) error {
	s.Logger.Log("ID", s.ID, "msg", "received GET STATUS msg from", "addr", from)

	buf := new(bytes.Buffer)
	msg := s.createStatusMessage(buf)
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, ok := s.peerMap[from]
	if !ok {
		return fmt.Errorf("peer not found")
	}

	return peer.Send(msg)
}

func (s *Server) createStatusMessage(buf *bytes.Buffer) *Message {
	statusMsg := &StatusMessage{
		CurrentLength: int64(len(s.chain.Headers())),
		ID:            s.ID,
	}

	if err := gob.NewEncoder(buf).Encode(statusMsg); err != nil {
		s.Logger.Log("err", err)
		return nil
	}
	msg := NewMessage(MessageTypeStatus, buf.Bytes(), s.ID)

	return msg
}

func (s *Server) processBlock(b *types.Block) error {
	fmt.Printf("processBlock: %+v\n", b)
	if err := s.chain.VerifyBlock(b); err != nil {
		return err
	}

	go s.broadcastBlock(b)

	return nil
}

func (s *Server) processTransaction(tx *types.Transaction) error {
	// Not all txs need to be added to the mempool immediately
	// Txs that are added are as follows:
	// 1. RFQRequestTx - added upon receipt from a client
	// 2. OpenRfqRequestTx - created/added by a validator no
	// 3. RFQResponseTx - created/added by a validator node
	hash := tx.Hash()
	s.Logger.Log("msg", "received tx", "hash", hash, "transType", tx.Type(), "mempool len", s.memPool.PendingCount())
	if s.memPool.Contains(hash) {
		return nil
	}

	if err := tx.Verify(); err != nil {
		return err
	}

	s.Logger.Log(
		"msg", "added new tx to pool",
		"hash", hash,
		"mempool len", s.memPool.PendingCount(),
	)

	// You'll need to add logic here to perform the type checking since I don't know what the type will look like

	go s.broadcastTx(tx)

	s.memPool.Add(tx)

	// og the RFQRequest has been verified we need to broadcast over websockets the start of a new tfq round
	if tx.Type() == types.RFQRequestTxType {
		s.Logger.Log("msg", "adding RFQRequestTx to event channel")
		s.chain.EventChan <- types.TxEvent{TxType: tx.Type(), TxHash: tx.Hash(), Transaction: tx}
	}

	return nil
}

// TODO: stop syncing when at highest block
func (s *Server) requestBlocksLoop(peer net.Addr, blocksIndex int64) error {
	ticker := time.NewTicker(6 * time.Second)

	for {

		headersLength := len(s.chain.Headers())
		// blocksIndex := int64(headersLength)
		if headersLength > int(blocksIndex) {
			s.Logger.Log("msg", "finished syncing", "addr", peer)
			return nil
		}

		s.Logger.Log("msg", "requesting blocks", "requesting headers index", headersLength, "addr", peer)

		getBlocksMsg := &GetBlocksMessage{
			From: uint64(blocksIndex),
			To:   uint64(headersLength),
		}
		buf := new(bytes.Buffer)
		if err := gob.NewEncoder(buf).Encode(getBlocksMsg); err != nil {
			return err
		}

		s.mu.RLock()
		defer s.mu.RUnlock()

		msg := NewMessage(MessageTypeGetBlocks, buf.Bytes(), s.ID)
		peer, ok := s.peerMap[peer]
		if !ok {
			return fmt.Errorf("peer %+s not found", peer.conn.RemoteAddr())
		}

		if err := peer.Send(msg); err != nil {
			s.Logger.Log("error", "failed to send to peer", "err", err, "peer", peer.conn.RemoteAddr())
		}

		<-ticker.C
	}
}

func (s *Server) broadcastBlock(b *types.Block) error {
	buf := &bytes.Buffer{}
	// if err := b.Encode(common.NewGobBlockEncoder(buf)); err != nil {
	// 	return err
	// }
	s.mu.Lock()
	defer s.mu.Unlock()
	msg := NewMessage(MessageTypeBlock, buf.Bytes(), s.ID)

	return s.broadcast(msg.Bytes())
}

func (s *Server) broadcastTx(tx *types.Transaction) error {
	buf := &bytes.Buffer{}
	// if err := tx.Encode(core.NewRLPTxEncoder(buf)); err != nil {
	// 	return err
	// }

	msg := NewMessage(MessageTypeTx, buf.Bytes(), s.ID)

	return s.broadcast(msg.Bytes())
}

func (s *Server) CreateNewBlock() error {
	// 1. get transactions from mempool
	// 2. create a new block
	currentHeader, err := s.chain.GetBlockHeader(s.chain.Height())
	if err != nil {
		return err
	}

	// TODO: change from adding all txs to pool - limit via some function later
	// To match the tx types
	txx := s.memPool.Pending()

	block, err := types.NewBlockFromPrevHeader(currentHeader, txx)
	if err != nil {
		return err
	}

	if err := block.Sign(*s.PrivateKey); err != nil {
		return err
	}

	if err := s.chain.VerifyBlock(block); err != nil {
		return err
	}

	s.memPool.ClearPending()

	go s.broadcastBlock(block)

	return nil
}

func (s *Server) Stop() {
	s.cancelFunc()
}

func genesisBlock() *types.Block {
	header := &types.Header{
		Version:   1,
		TxHash:    common.Hash{},
		Height:    big.NewInt(0),
		Timestamp: uint64(time.Now().UnixNano()),
	}

	privKey := cryptoocax.GeneratePrivateKey()
	pubKey := privKey.PublicKey()
	// hasher := types.NewOcaxHasher()
	txs := []*types.Transaction{}
	b := types.NewBlock(header, txs, pubKey)
	b.Validator = pubKey

	if err := b.Sign(privKey); err != nil {
		panic(err)
	}

	return b
}

func deleteDirectoryIfExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.RemoveAll(path)
}
