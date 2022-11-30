package p2p

import (
	"crypto/ecdsa"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func TestValidatedAddressList(t *testing.T) {
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
				// Logger:         testlog.Logger(t, log.LvlTrace),
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
	fmt.Println("Wait 10 seconds for node to discover each other")
	time.Sleep(10 * time.Second)

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

	// Bootnode whitelist / add a new pubkey
	privKeyToWhitelist := nonValidatedPrivKeys[0]
	pubKeyToWhitelist := privKeyToWhitelist.PublicKey
	addressToWhitelist := crypto.PubkeyToAddress(pubKeyToWhitelist)
	validatedAddress[addressToWhitelist.String()] = true

	fmt.Println("Address to be whitelisted:", addressToWhitelist)
	bootServer.AddValidatedPubkey(pubKeyToWhitelist)

	fmt.Println("Wait 20 seconds for discover refresh")
	time.Sleep(20 * time.Second)

	// Bootnode now contains whitelisted addresses
	for _, peer := range bootServer.Peers() {
		pubkey := peer.Node().Pubkey()
		address := crypto.PubkeyToAddress(*pubkey)
		if !validatedAddress[address.String()] && address.String() != bootAddress.String() {
			t.Error("Connected to non validated node")
		}
	}

	// Blakclist / remove the previously added address
	pubKeyToBlacklist := pubKeyToWhitelist
	addressToBlacklist := addressToWhitelist
	delete(validatedAddress, addressToBlacklist.String())

	fmt.Println("Address to be blacklisted:", addressToBlacklist)
	bootServer.RemoveValidatedPubkey(pubKeyToBlacklist)

	fmt.Println("Wait 5 seconds for bootnode to disconnect with blacklisted node")
	time.Sleep(5 * time.Second)

	//  Bootnode only connected to validated nodes
	if len(validatedAddress) != bootServer.PeerCount() {
		t.Error("Bootnode peers doesn't match with validated address list")
	}
	for _, peer := range bootServer.Peers() {
		pubkey := peer.Node().Pubkey()
		address := crypto.PubkeyToAddress(*pubkey)
		if !validatedAddress[address.String()] && address.String() != bootAddress.String() {
			t.Error("Connected to non validated node")
		}
	}

}

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
				// Logger:         testlog.Logger(t, log.LvlTrace),
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
	fmt.Println("Wait 10 seconds for node to discover each other")
	time.Sleep(10 * time.Second)

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
