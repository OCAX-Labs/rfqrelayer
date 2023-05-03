package main

import (
	"log"

	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/OCAX-labs/rfqrelayer/network"
)

func main() {
	validatorPrivKey := cryptoocax.GeneratePrivateKey()
	localNode := makeServer("LOCAL_NODE", &validatorPrivKey, ":3000", []string{":4000"}, ":9999")

	go localNode.Start()

	remoteNode := makeServer("REMOTE_A", nil, ":4000", nil, "")
	go remoteNode.Start()

	// remoteNodeB := makeServer("REMOTE_B", nil, ":5000", nil, "")
	// go remoteNodeB.Start()

	// go func() {
	// 	time.Sleep(11 * time.Second)
	// 	lateNode := makeServer("LATE_NODE", nil, ":6000", []string{":4000"}, "")
	// 	go lateNode.Start()

	// }()

	select {}
}

func makeServer(id string, pk *cryptoocax.PrivateKey, addr string, seedNodes []string, apiListenAddr string) *network.Server {
	options := network.ServerOptions{
		APIListenAddr: apiListenAddr,
		SeedNodes:     seedNodes,
		ListenAddr:    addr,
		PrivateKey:    pk,
		ID:            id,
	}
	log.Default().Println("options", options, "server:", options.ID)
	s, err := network.NewServer(options)
	if err != nil {
		log.Fatal(err)
	}
	return s
}
