package main

import (
	"flag"
	"fmt"
	log "github.com/golang/glog"
	"github.com/winteraz/cryptopay"
	"github.com/winteraz/cryptopay/blockchain"
	"github.com/winteraz/cryptopay/wallet"
	"net/http"
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
	depth := flag.Int("depth", 0, "depth of address generation")
	accts := flag.Int("accts", 1, "number of accounts")
	coin := flag.Int("coin", 0, "the coin of the wallet, default is 0 (BTC)")

	move := flag.Bool("move", false, "move the wallet to a new address")
	toAddr := flag.String("toAddr", "", "the address to send the wallet to")

	balance := flag.Bool("balance", false, "get the balance")
	xpub := flag.String("xpub", "", "xpub to get the balance from")

	flag.Parse()
	trimString(mnemonicIn, pass)

	switch {
	case *balance:
		balanceFN(cryptopay.CoinType(*coin), *xpub)
	case *move:
		moveWallet(*mnemonicIn, *pass, cryptopay.CoinType(*coin), *toAddr)
	case *genAddr:
		generateAddr(*mnemonicIn, *pass, uint32(*accts), uint32(*depth), cryptopay.CoinType(*coin))
	default:
		generate(mnemonicIn, pass)
	}
}

func generateAddr(mnemonic, pass string, accts, depth uint32, coin cryptopay.CoinType) {
	if mnemonic == "" {
		log.Fatalf("Invalid mnemonic")
	}
	var sa []string
	kind := false // external address type/kind
	for acct := uint32(0); acct <= accts; acct++ {
		w, err := wallet.FromMnemonic(mnemonic, pass, blockchain.New(http.DefaultClient), coin, acct)
		if err != nil {
			log.Fatal(err)
		}

		addra, err := w.Addresses(nil, kind, depth)
		if err != nil {
			log.Fatal(err)
		}
		sa = append(sa, addra...)
	}
	fmt.Printf("mnemonic %v\n pass %q, addresses \n %q", mnemonic, pass, sa)
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

func moveWallet(mnemonic, pass string, coin cryptopay.CoinType, toAddrPub string) {
	if mnemonic == "" {
		log.Fatalf("Invalid mnemonic")
	}
	const accountsGap, addressGap = uint32(4), uint32(20)
	txaa := make(map[uint32][][]byte)
	for account := uint32(0); account <= accountsGap; account++ {
		w, err := wallet.FromMnemonic(mnemonic, pass, blockchain.New(http.DefaultClient), coin, account)
		if err != nil {
			log.Fatal(err)
		}

		txa, err := w.Move(nil, toAddrPub, addressGap)
		if err != nil {
			log.Fatal(err)
		}
		txaa[account] = txa
	}
	for account, txa := range txaa {
		for _, tx := range txa {
			fmt.Printf("%s: account %v TX  %s", coin, account, tx)
		}
	}
}

func balanceFN(coin cryptopay.CoinType, xpub string) {
	w, err := wallet.FromPublic(xpub, coin, blockchain.New(http.DefaultClient))
	if err != nil {
		log.Fatal(err)
	}
	const addressGap = uint32(20)
	kind := false
	amountM, err := w.Balance(nil, kind, addressGap)
	if err != nil {
		log.Fatal(err)
	}
	var amount uint64
	for _, v := range amountM {
		amount += v
	}

	kind = true
	amountInternalM, err := w.Balance(nil, kind, addressGap)
	if err != nil {
		log.Fatal(err)
	}
	var amountInternal uint64
	for _, v := range amountInternalM {
		amountInternal += v
	}

	fmt.Printf("Amount external: %v\nAccount Internal %v\nTotalBalance %v\n\nAmountMap %q\n\nAmountInternalMap %q",
		amount, amountInternal, (amount + amountInternal), amountM, amountInternalM)
}
