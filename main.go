package main

import (
	"log"
	"os"

	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/OCAX-labs/rfqrelayer/keystore"
	"github.com/OCAX-labs/rfqrelayer/network"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	ks := keystore.NewKeyStore()

	// Keystore path
	keyStorePath := ".keystore/keystore.json"

	// Create .keystore directory if not exist
	if _, err := os.Stat(".keystore/"); os.IsNotExist(err) {
		err = os.Mkdir(".keystore/", 0755)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Load the passphrase from the .env file
	passphrase := os.Getenv("PASSPHRASE")

	// Load or create key
	var validatorPrivKey cryptoocax.PrivateKey
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		// If the keystore does not exist, generate a new key
		err := ks.GenerateKeyToFile(passphrase, keyStorePath)
		if err != nil {
			log.Fatal(err)
		}
		validatorPrivKey = *ks.PrivateKey
	} else {
		// If the keystore exists, load the key
		err := ks.LoadKeyFromFile(passphrase, keyStorePath)
		if err != nil {
			log.Fatal(err)
		}
		validatorPrivKey = *ks.PrivateKey
	}

	localNode := makeServer("LOCAL_NODE", &validatorPrivKey, ":3000", []string{":4000"}, ":9999")

	go localNode.Start()

	remoteNode := makeServer("REMOTE_A", nil, ":4000", []string{":4000"}, ":9998")
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
