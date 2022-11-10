package p2p

import (
	"crypto/ecdsa"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func TestPermissionDiscovery(t *testing.T) {
	validatedPrivKeys := []*ecdsa.PrivateKey{newkey(), newkey()}
	nonValidatedPrivKeys := []*ecdsa.PrivateKey{newkey(), newkey()}

	bootPrvKey := newkey()
	bootAddress := crypto.PubkeyToAddress(bootPrvKey.PublicKey)

	validatedAddress := make(map[string]bool)

	for _, key := range validatedPrivKeys {
		pubkey := key.PublicKey
		address := crypto.PubkeyToAddress(pubkey)
		validatedAddress[address.String()] = true
	}

	// Create bootnode with permission-ed pubkey
	bootServer := &Server{
		Config: Config{
			PrivateKey:       bootPrvKey,
			MaxPeers:         50,
			ListenAddr:       "0.0.0.0:0",
			ValidatedAddress: validatedAddress,
		},
	}

	bootServer.Start()

	bootServerEnode, err := enode.ParseV4(bootServer.NodeInfo().Enode)
	if err != nil {
		panic(err.Error())
	}

	nonValidatedServers := []*Server{}

	// Create non validated node
	for i, key := range nonValidatedPrivKeys {
		server := &Server{
			Config: Config{
				Name:           fmt.Sprint("NonValidatedServer", ":", i),
				PrivateKey:     key,
				MaxPeers:       50,
				ListenAddr:     "0.0.0.0:0",
				BootstrapNodes: []*enode.Node{bootServerEnode},
			},
		}
		server.Start()
		nonValidatedServers = append(nonValidatedServers, server)
	}

	servers := []*Server{}

	// Create validated node
	for i, key := range validatedPrivKeys {
		server := &Server{
			Config: Config{
				Name:           fmt.Sprint("Server", ":", i),
				PrivateKey:     key,
				MaxPeers:       50,
				ListenAddr:     "0.0.0.0:0",
				BootstrapNodes: []*enode.Node{bootServerEnode},
			},
		}
		server.Start()
		servers = append(servers, server)
	}

	// Wait for node find each others
	time.Sleep(10 * time.Second)
	fmt.Println("Wait 10 seconds for node to discover each other")

	// Non validated node shouldn't discover any nodes when the bootnode is permissioned
	for _, nonValidatedServer := range nonValidatedServers {
		if nonValidatedServer.PeerCount() > 0 {
			t.Error("Non validated node discovered peer")
		}
	}

	// Node only discover validated nodes
	for _, server := range servers {
		peers := server.Peers()
		for _, peer := range peers {
			pubkey := peer.Node().Pubkey()
			address := crypto.PubkeyToAddress(*pubkey)
			if !validatedAddress[address.String()] && address.String() != bootAddress.String() {
				t.Error("Connected to non validated node")
			}
		}
	}

	// Bootnode only connected to validated nodes
	for _, peer := range bootServer.Peers() {
		pubkey := peer.Node().Pubkey()
		address := crypto.PubkeyToAddress(*pubkey)
		if !validatedAddress[address.String()] && address.String() != bootAddress.String() {
			t.Error("Connected to non validated node")
		}
	}

}
