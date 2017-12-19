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

	childPublic, err := pub.PublicAddr(cointTyp, account, index)
	if err != nil {
		panic(err)
	}
	childPrivate, err := priv.PrivateKey(cointTyp, account, index)
	if err != nil {
		panic(err)
	}

	fmt.Printf("mn %s \n", mnemonic)
	fmt.Printf("BTC master wif %s\n", masterWIF)
	fmt.Printf("BTC publicRoot %s\n\n", pub.Base58())
	fmt.Printf("BTC Child first priv %s\n", childPrivate)
	fmt.Printf("BTC Child first pub %s\n\n\n\n", childPublic)

	cointTyp = cryptopay.ETH
	rootPrivEIP55, _ := priv.RootPrivateEIP55()
	rootPubEIP55, _ := pub.RootPublicEIP55()
	childPublic, err = pub.PublicAddr(cointTyp, account, index)
	if err != nil {
		panic(err)
	}
	childPrivate, err = priv.PrivateKey(cointTyp, account, index)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ETH private Root  %s\n", rootPrivEIP55)
	fmt.Printf("ETH publicRoot %s\n\n", rootPubEIP55)
	fmt.Printf("ETH Child first priv %s\n", childPrivate)
	fmt.Printf("ETH Child first pub %s\n", childPublic)
}
