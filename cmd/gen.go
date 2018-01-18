package main

import (
	"flag"
	"fmt"
	log "github.com/golang/glog"
	"github.com/winteraz/cryptopay"
	"github.com/winteraz/cryptopay/cmd/util"
	"strings"
)

func trimString(s ...*string) {
	for _, v := range s {
		*v = strings.TrimPrefix(*v, `"`)
		*v = strings.TrimSuffix(*v, `"`)
	}
	return
}

func main() {
	pass := flag.String("pass", "", "password to harden the key generation")
	mnemonicIn := flag.String("mnemonic", "", "if set it will generate the keys from the mnemonic")
	genAddr := flag.Bool("addr", false, "if set it will addresses(public and private")
	depth := flag.Int("depth", 10, "depth of address generation")
	accts := flag.Int("accts", 10, "number of accounts")
	coin := flag.Int("coin", 0, "the coin of the wallet, default is 0 (BTC)")

	move := flag.Bool("move", false, "move the wallet to a new address")
	toAddr := flag.String("toAddr", "", "the address to send the wallet to")

	balance := flag.Bool("balance", false, "get the balance")
	xpub := flag.String("xpub", "", "xpub to get the balance from")

	ethEndpointHost := flag.String("ethHost", "", "the hostname of the ETH endpoint RPC")
	flag.Parse()
	trimString(mnemonicIn, pass)

	switch {
	case *balance:
		req := &util.Request{
			ExtendedPublic: *xpub,
			Coin:           cryptopay.CoinType(*coin),
		}
		balanceFN(req, *ethEndpointHost, uint32(*accts), uint32(*depth))
	case *move:
		req := &util.Request{
			Mnemonic: *mnemonicIn,
			Passwd:   *pass,
			Coin:     cryptopay.CoinType(*coin),
		}
		moveWallet(req, *ethEndpointHost, *toAddr, uint32(*accts), uint32(*depth))
	case *genAddr:
		req := &util.Request{
			Mnemonic: *mnemonicIn,
			Passwd:   *pass,
			Coin:     cryptopay.CoinType(*coin),
		}
		generateAddr(req, *ethEndpointHost, uint32(*accts), uint32(*depth))
	default:
		generate(mnemonicIn, pass)
	}
}

func generateAddr(req *util.Request, ethEndpointHost string, accts, depth uint32) {
	var sa []string
	kind := false // external address type/kind
	for acct := uint32(0); acct <= accts; acct++ {
		w, err := req.WalletAccount(nil, ethEndpointHost, acct)
		if err != nil {
			log.Fatal(err)
		}

		addra, err := w.Addresses(nil, kind, depth)
		if err != nil {
			log.Fatal(err)
		}
		sa = append(sa, addra...)
	}
	fmt.Printf("req %#v\n addresses \n %q", *req, sa)
}

func generate(mnemonicIn, pass *string) {
	var priv *cryptopay.Key
	var err error
	var mnemonic string
	if *mnemonicIn == "" {
		priv, _, mnemonic, err = cryptopay.NewMaster(*pass)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		mnemonic = *mnemonicIn
		priv, _, err = cryptopay.NewFromMnemonic(mnemonic, *pass)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("mnemonic %q \n pass %q\n", mnemonic, *pass)

	coins := []cryptopay.CoinType{cryptopay.BTC, cryptopay.BCH, cryptopay.ETH}
	account := uint32(0)
	index := uint32(0)
	for _, coin := range coins {
		childPrivate, err := priv.PrivateKey(coin, account, false, index)
		if err != nil {
			log.Fatal(err)
		}
		extendedAccountPub, err := priv.DeriveExtendedAccountKey(false, coin, account)
		if err != nil {
			log.Fatal(err)
		}
		change := false // external
		childPublic, err := extendedAccountPub.DeriveExtendedAddr(coin, change, index)
		if err != nil {
			log.Fatal(err)
		}

		rootKey, err := priv.PrivateRoot(coin)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", coin.String())
		fmt.Printf("masterKey(coin native format)  %q\n", rootKey)
		fmt.Printf("masterKey(bip-32/base58 formt)  %q\n", priv.Base58())
		fmt.Printf("BIP32 Account Extended Public Key %q\n", extendedAccountPub.Base58())
		fmt.Printf("first child External private %q\n", childPrivate)
		fmt.Printf("first child External address %q\n\n", childPublic)
	}

}

func moveWallet(req *util.Request, ethEndpointHost, toAddrPub string, accountsGap, addressGap uint32) {
	txaa, err := req.MoveWallet(nil, ethEndpointHost, toAddrPub, accountsGap, addressGap)
	if err != nil {
		log.Fatal(err)
	}
	for account, txa := range txaa {
		for _, tx := range txa {
			fmt.Printf("%s: account %v TX  %s", req.Coin, account, tx)
		}
	}
}

func balanceFN(req *util.Request, ethEndpointHost string, accountsGap, addressGap uint32) {
	var accountInternal = make(map[uint32]map[string]uint64)
	var accountExternal = make(map[uint32]map[string]uint64)
	accountExternal, accountInternal, err := req.Balance(nil, ethEndpointHost, accountsGap, addressGap)
	if err != nil {
		log.Fatal(err)
	}

	var amount, amountInternal uint64
	for _, m := range accountExternal {
		for _, v := range m {
			amount += v
		}
	}
	for _, m := range accountInternal {
		for _, v := range m {
			amountInternal += v
		}
	}

	fmt.Printf("Amount external: %v\nAccount Internal %v\nTotalBalance %v\n\nAmountMap %q\n\nAmountInternalMap %q",
		amount, amountInternal, (amount + amountInternal), accountExternal, accountInternal)

}
