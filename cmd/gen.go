package main

import (
	"context"
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

	broadcast := flag.Bool("broadcast", false, "broadcast the transactions (if move is used)")
	move := flag.Bool("move", false, "move the wallet to a new address")
	toAddr := flag.String("toAddr", "", "the address to send the wallet to")

	balance := flag.Bool("balance", false, "get the balance")
	xpub := flag.String("xpub", "", "xpub to get the balance from")

	remoteHost := flag.String("remoteHost", "", "the hostname of the RPC endpoint")
	flag.Parse()
	defer log.Flush()
	trimString(mnemonicIn, pass)
	if *remoteHost == "" {
		log.Errorf("Invalid remoteHost %v", *remoteHost)
		return
	}
	cx := context.Background()
	switch {
	case *balance:
		req := &util.Request{
			Mnemonic:       *mnemonicIn,
			ExtendedPublic: *xpub,
			Coin:           cryptopay.CoinType(*coin),
		}
		balanceFN(cx, req, *remoteHost, uint32(*accts), uint32(*depth))
	case *move:
		req := &util.Request{
			Mnemonic: *mnemonicIn,
			Passwd:   *pass,
			Coin:     cryptopay.CoinType(*coin),
		}
		moveWallet(cx, req, *remoteHost, *toAddr, uint32(*accts), uint32(*depth), *broadcast)
	case *genAddr:
		req := &util.Request{
			Mnemonic: *mnemonicIn,
			Passwd:   *pass,
			Coin:     cryptopay.CoinType(*coin),
		}
		generateAddr(cx, req, *remoteHost, uint32(*accts), uint32(*depth))
	default:
		generate(cx, mnemonicIn, pass)
	}
}

func generateAddr(cx context.Context, req *util.Request, remoteHost string, accts, depth uint32) {
	var sa []string
	kind := false // external address type/kind
	for acct := uint32(0); acct <= accts; acct++ {
		w, err := req.WalletAccount(cx, remoteHost, acct)
		if err != nil {
			log.Error(err)
			return
		}
		const startIndex uint32 = 0
		addra, err := w.Addresses(cx, kind, startIndex, depth)
		if err != nil {
			log.Fatal(err)
		}
		sa = append(sa, addra...)
	}
	fmt.Printf("req %#v\n addresses \n %q", *req, sa)
	kind = true
	for acct := uint32(0); acct <= accts; acct++ {
		w, err := req.WalletAccount(cx, remoteHost, acct)
		if err != nil {
			log.Error(err)
			return
		}
		const startIndex uint32 = 0
		addra, err := w.Addresses(cx, kind, startIndex, depth)
		if err != nil {
			log.Fatal(err)
		}
		sa = append(sa, addra...)
	}
	log.Infof("Private addresses %q", sa)
}

func generate(cx context.Context, mnemonicIn, pass *string) {
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

func moveWallet(cx context.Context, req *util.Request, remoteHost, toAddrPub string, accountsGap, addressGap uint32, broadcast bool) {
	txaa, err := req.MoveWallet(cx, remoteHost, toAddrPub, accountsGap, addressGap)
	if err != nil {
		log.Error(err)
		return
	}
	var txlist []string
	for account, txa := range txaa {
		for _, tx := range txa {
			txlist = append(txlist, tx)
			fmt.Printf("%s: account %v TX  %s\n", req.Coin, account, tx)
		}
	}
	if len(txlist) == 0 {
		return
	}
	br, err := req.Broadcaster(cx, remoteHost)
	if err != nil {
		log.Error(err)
		return
	}
	txErr, err := br.Broadcast(cx, txlist...)
	if err != nil {
		log.Error(err)
		return
	}
	for tx, err := range txErr {
		if err != nil {
			log.Errorf("TX %s, err %v", tx, err)
		}
	}

}

func balanceFN(cx context.Context, req *util.Request, remoteHost string, accountsGap, addressGap uint32) {

	balance, err := req.Balance(cx, remoteHost, accountsGap, addressGap)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf(" TotalBalance %v\n\nAmountMap %q\n\nAmountInternalMap %q",
		balance.Total, balance.External, balance.Internal)

}
