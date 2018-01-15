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
	flag.Parse()

	trimString(mnemonicIn, pass)

	switch {
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
	w, err := wallet.FromMnemonic(mnemonic, pass, blockchain.New(http.DefaultClient))
	if err != nil {
		log.Fatal(err)
	}
	var sa []string
	for acct := uint32(0); acct <= accts; acct++ {
		addra, err := w.Addresses(nil, acct, depth, cryptopay.BTC)
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
		childPrivate, err := priv.PrivateKey(coin, account, index)
		if err != nil {
			log.Fatal(err)
		}
		extendedPub, err := priv.DeriveExtendedKey(false, coin, account)
		if err != nil {
			log.Fatal(err)
		}
		childPublic, err := extendedPub.DerivePublicAddr(coin, index)
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
		fmt.Printf("BIP32 Extended Public Key %q\n", extendedPub.Base58())
		fmt.Printf("first child private %q\n", childPrivate)
		fmt.Printf("first child address %q\n\n", childPublic)
	}

}

func moveWallet(mnemonic, pass string, coin cryptopay.CoinType, toAddr string) {
	if mnemonic == "" {
		log.Fatalf("Invalid mnemonic")
	}
	w, err := wallet.FromMnemonic(mnemonic, pass, blockchain.New(http.DefaultClient))
	if err != nil {
		log.Fatal(err)
	}
	const accountsGap, addressGap = uint32(4), uint32(20)
	txa, err := w.Move(nil, map[cryptopay.CoinType]string{coin: toAddr}, accountsGap, addressGap)
	if err != nil {
		log.Fatal(err)
	}
	for coin, tx := range txa {
		fmt.Printf("%s: %s", coin, tx)
	}
}
