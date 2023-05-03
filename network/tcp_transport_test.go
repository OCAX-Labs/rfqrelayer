package network

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConnect(t *testing.T) {
	peerCh := make(chan *TCPPeer)
	rpcCh := make(chan RPC)
	tr := NewTCPTransport(":3000", peerCh, rpcCh)

	assert.Equal(t, tr.listenAddr, ":3000")
}

// Test TCPTransport Start() and Stop()
func TestTCPTransportStartStop(t *testing.T) {
	peerCh := make(chan *TCPPeer)
	rpcCh := make(chan RPC)
	transport := NewTCPTransport("localhost:8081", peerCh, rpcCh)

	err := transport.Start()
	if err != nil {
		t.Fatalf("Failed to start transport: %v", err)
	}

	t.Run("TestTCPTransportStartStop", func(t *testing.T) {
		time.Sleep(1 * time.Second)

		// Try to dial to the server to ensure it's running.
		conn, err := net.Dial("tcp", "localhost:8081")
		if err != nil {
			t.Fatalf("Failed to connect to the server: %v", err)
		}
		conn.Close()
		transport.Stop()

		// Add a delay to ensure the server has stopped.
		time.Sleep(1 * time.Second)

		// Try to dial to the server to ensure it's stopped.
		var newConn net.Conn
		newConn, err = net.Dial("tcp", "localhost:8081")
		if err == nil {
			t.Fatalf("Server is still running after Stop()")
			newConn.Close()
		}
	})
	// Add a delay to ensure the server has started.

}

// TestAddingAndRemovingAPeer
func TestAddingAndRemovingAPeer(t *testing.T) {
	peerCh := make(chan *TCPPeer)
	rpcCh := make(chan RPC)
	transport := NewTCPTransport("localhost:8082", peerCh, rpcCh)

	err := transport.Start()
	if err != nil {
		t.Fatalf("Failed to start transport: %v", err)
	}

	t.Run("TestAddingAndRemovingAPeer", func(t *testing.T) {
		// Simulate a peer connection
		go func() {
			_, err := net.Dial("tcp", "localhost:8082")
			if err != nil {
				t.Errorf("Failed to connect as a peer: %v", err)
			}
		}()

		// Wait for the peer to be added
		peer := <-peerCh
		if !transport.HasPeer(peer) {
			t.Errorf("Peer was not added to transport")
		}

		// Remove the peer
		peer.cancelFunc()
		transport.RemovePeer(peer)
		if transport.HasPeer(peer) {
			t.Errorf("Peer was not removed from transport")
		} // ...
	})

	transport.Stop()

}

// TestReadingAndWritingToRPCChannel
func TestReadingAndWritingToRPCChannel(t *testing.T) {
	peerCh := make(chan *TCPPeer)
	rpcCh := make(chan RPC, 256) // Buffered channel for easier testing
	transport := NewTCPTransport("localhost:4001", peerCh, rpcCh)

	err := transport.Start()
	if err != nil {
		t.Fatalf("Failed to start transport: %v", err)
	}

	t.Run("TestReadingAndWritingToRPCChannel", func(t *testing.T) {
		// Start listening for peers in a goroutine.
		go func() {
			select {
			case peer := <-peerCh:
				fmt.Printf("Test received a peer: %+v\n", peer.conn)
			case <-time.After(10 * time.Second):
				fmt.Println("Test timed out waiting for peer")
			}
		}()

		// Simulate a peer connection
		go func() {
			conn, err := net.Dial("tcp", "localhost:4001")
			if err != nil {
				t.Errorf("Failed to connect as a peer: %v", err)
				return
			}
			defer conn.Close() // Close connection after writing the payload

			_, err = conn.Write([]byte("test payload"))

			if err != nil {
				t.Errorf("Failed to write payload: %v", err)
			}
		}()
		// Wait for the RPC to be received
		select {
		case rpc := <-rpcCh:
			payloadBytes := make([]byte, 12) // Length of "test payload"
			_, err = rpc.Payload.Read(payloadBytes)
			if err != nil {
				t.Errorf("Failed to read payload: %v", err)
			}

			if string(payloadBytes) != "test payload" {
				t.Errorf("Payload does not match expected: %v", string(payloadBytes))
			}
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for RPC message")
		}
	})

	transport.Stop()

}
