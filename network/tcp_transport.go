package network

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var timeout = 10 * time.Minute

type TCPPeer struct {
	ID        string
	conn      net.Conn
	transport *TCPTransport // Adding a reference to the transport

	Outgoing   bool
	ctx        context.Context
	cancelFunc context.CancelFunc
}

func (p *TCPPeer) Send(msg *Message) error {

	payload := msg.Bytes()

	p.conn.SetWriteDeadline(time.Now().Add(timeout)) // Set a write deadline
	_, err := p.conn.Write(payload)
	if err != nil {
		fmt.Printf("Failed to send, reconnecting: %v\n", err)
		err = p.reconnect()
		if err != nil {
			fmt.Printf("Failed to reconnect: %v\n", err)
		}
	}
	return err
}

func (p *TCPPeer) SendBytesPayload(payload []byte) error {
	p.conn.SetWriteDeadline(time.Now().Add(timeout)) // Set a write deadline
	_, err := p.conn.Write(payload)
	if err != nil {
		fmt.Printf("Failed to send, reconnecting: %v\n", err)
		err = p.reconnect()
		if err != nil {
			fmt.Printf("Failed to reconnect: %v\n", err)
		}
	}
	return err
}

func (p *TCPPeer) reconnect() error {
	var err error
	for i := 0; i < 3; i++ { // try to reconnect 3 times
		p.conn, err = net.Dial("tcp", p.conn.RemoteAddr().String())
		if err == nil {
			return nil // reconnected successfully
		}
		time.Sleep(1 * time.Second) // wait before retrying
	}
	return err // couldn't reconnect after 3 attempts
}

func (t *TCPTransport) acceptLoop(errors chan<- error) {
	for {

		select {
		case <-t.ctx.Done():
			fmt.Println("TCP TRANSPORT: Stopping accept loop")
			return
		default:
		}

		conn, err := t.listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection err: [%+v]\n", err)
			errors <- fmt.Errorf("error accepting connection: %w", err)
			continue
		}
		peerCtx, cancel := context.WithCancel(t.ctx)
		defer cancel()

		peer := &TCPPeer{
			ID:         t.ID,
			conn:       conn,
			ctx:        peerCtx,
			cancelFunc: cancel,
		}

		t.peerCh <- peer
		t.peerMutex.Lock()
		t.activePeers[peer] = struct{}{}
		t.peerMutex.Unlock()
		fmt.Printf("Accepted connection from [%+v]\n", peer.conn)

		go func(p *TCPPeer) {
			fmt.Printf("Starting read loop for [%+v]\n", p.conn)
			p.readLoop(t.rpcCh, errors) // pass error channel to readLoop
			fmt.Printf("Closing peer [%+v]\n", p.conn)
			t.closePeer(p)
		}(peer)
	}
}

func (t *TCPTransport) closePeer(p *TCPPeer) {
	t.peerMutex.Lock()
	p.conn.Close()
	delete(t.activePeers, p)
	t.peerMutex.Unlock()
	p.cancelFunc()
}

func (t *TCPTransport) AddPeer(peer *TCPPeer) {
	t.peerMutex.Lock()
	defer t.peerMutex.Unlock()
	t.activePeers[peer] = struct{}{}
}

func (t *TCPTransport) RemovePeer(peer *TCPPeer) {
	t.peerMutex.Lock()
	defer t.peerMutex.Unlock()
	delete(t.activePeers, peer)
}

func (t *TCPTransport) HasPeer(peer *TCPPeer) bool {
	t.peerMutex.Lock()
	defer t.peerMutex.Unlock()
	_, ok := t.activePeers[peer]
	return ok
}

func (p *TCPPeer) readLoop(rpcCh chan RPC, errors chan<- error) {
	defer close(errors)
	buf := make([]byte, 4096)

	for {
		select {
		case <-p.ctx.Done():
			fmt.Printf("Stopping read loop for [%+v]\n", p.conn)
			return
		default:
		}

		n, err := p.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("Connection closed\n")
				errors <- fmt.Errorf("connection closed by peer: %w", err)
				return
			} else {
				fmt.Printf("Error reading from [%+v]\n", p.conn)
				err = p.reconnect()
				if err != nil {
					fmt.Printf("Failed to reconnect: %v\n", err)
					errors <- fmt.Errorf("failed to reconnect to peer: %w", err)
					return
				}
				continue
			}
		}

		msg := buf[:n]
		rpcCh <- RPC{
			From:    p.conn.RemoteAddr(),
			Payload: bytes.NewReader(msg),
		}
	}
}

type TCPTransport struct {
	ID         string
	peerCh     chan *TCPPeer
	listenAddr string
	listener   net.Listener
	rpcCh      chan RPC

	activePeers map[*TCPPeer]struct{}
	peerMutex   sync.Mutex // Protects activePeers

	ctx        context.Context
	cancelFunc context.CancelFunc
}

func NewTCPTransport(id string, addr string, peerCh chan *TCPPeer, rpcCh chan RPC) *TCPTransport {
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPTransport{
		ID:          id,
		peerCh:      peerCh,
		rpcCh:       rpcCh,
		listenAddr:  addr,
		ctx:         ctx,
		cancelFunc:  cancel,
		activePeers: make(map[*TCPPeer]struct{}),
	}
}

func (t *TCPTransport) Start() error {
	ln, err := net.Listen("tcp", t.listenAddr)
	if err != nil {
		return err
	}

	t.listener = ln

	errors := make(chan error)
	go t.acceptLoop(errors)

	fmt.Println("TCP TRANSPORT: Listening on port:", t.listenAddr)

	return nil
}

// When stopping, cancel the context.
func (t *TCPTransport) Stop() {
	t.cancelFunc()
	t.listener.Close()
}
