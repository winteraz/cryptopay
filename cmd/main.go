package main

import (
	"fmt"
	"github.com/winteraz/cryptopay"
)

func main() {
	pass := "somepass"

	priv, pub, mnemonic, err := cryptopay.NewMaster(pass)
	if err != nil {
		panic(err)
	}

	// priv, pub, err := cryptopay.NewFromMnemonic(mnemonic, pass)
	// master key/wallet
	masterWIF, err := priv.RootWIF()
	if err != nil {
		panic(err)
	}
	account := uint32(0)
	index := uint32(1)
	cointTyp := cryptopay.BTC

	btcPublic, err := pub.PublicAddr(cointTyp, account, index)
	if err != nil {
		panic(err)
	}
	btcPrivate, err := priv.PrivateKey(cointTyp, account, index)
	if err != nil {
		panic(err)
	}
	fmt.Printf("mn %s \n", mnemonic)
	fmt.Printf("master wif %s\n", masterWIF)
	fmt.Printf("publicRoot %s\n\n", pub.Base58())
	fmt.Printf("BTC first priv %s\n", btcPrivate)
	fmt.Printf("BTC first pub %s\n", btcPublic)

}
