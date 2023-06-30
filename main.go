package main

import (
	"fmt"
	"log"
	"os"

	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"
	"github.com/OCAX-labs/rfqrelayer/keystore"
	"github.com/OCAX-labs/rfqrelayer/network"
	"github.com/joho/godotenv"
)

const (
	keyStoreDir  = "./.keystore"
	keyStoreFile = "validator.json"
	keyStorePath = keyStoreDir + "/" + keyStoreFile
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	var ks *keystore.KeyStore
	fmt.Printf("PASSPHRASE: %s\n", os.Getenv("PASSPHRASE"))
	if os.Getenv("PASSPHRASE") != "" {
		// check if a keystore exists and load it
		// if not, generate a new one
		// and fetch private key from keystore
		fmt.Printf("keyStoreDir: %v\n", keyStoreDir)
		if _, err := os.Stat(keyStoreDir); os.IsNotExist(err) {
			err := os.MkdirAll(keyStoreDir, os.ModePerm)
			fmt.Printf("err: %v\n", err)
			if err != nil {
				log.Fatalf("Failed to create directory: %v", err)
			}

			// generate a new keystore
			ks = keystore.NewKeyStore()
			err = ks.GenerateKeyToFile(os.Getenv("PASSPHRASE"), keyStorePath)
			fmt.Printf("err: %v\n", err)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			// load keystore
			ks = keystore.NewKeyStore()
			err := ks.LoadKeyFromFile(os.Getenv("PASSPHRASE"), keyStorePath)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	fmt.Printf("ks %+v\n", ks)
	localNode := makeServer("LOCAL_NODE", ks.PrivateKey, ":3000", []string{":4000"}, ":9999")

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
