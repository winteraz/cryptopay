package main

import (
	"flag"
	"fmt"
	"strings"
	"github.com/winteraz/cryptopay"
	"github.com/winteraz/cryptopay/wallet"
)

func trimString(s ...*string){
	for _, v := range s{
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
	coinType := flag.Int("coin", 0, "coin type (0 is for bitcoin)")
	flag.Parse()

	trimString(mnemonicIn, pass)

	switch {
	case *genAddr:
		generateAddr(*mnemonicIn, *pass, uint32(*accts),uint32(*depth),  cryptopay.CoinType(*coinType))
	default:
		generate(mnemonicIn, pass)
	}
}

func generateAddr(mnemonic, pass string, accts, depth uint32, coin cryptopay.CoinType) {
	if mnemonic == ""{
		panic("Invalid mnemonic")
	}
	w, err := wallet.FromMnemonic(mnemonic, pass, nil )
	if err != nil {
		panic(err)
	}
	var sa []string
	for acct := uint32(0); acct<= accts; acct++{
		addra, err := w.Addresses(nil, acct, depth, cryptopay.BTC)
		if err != nil {
			panic(err)
		}
		sa = append(sa, addra...)
	}
		fmt.Printf("mnemonic %v\n pass %q, addresses \n %q", mnemonic, pass, sa)
}

func generate(mnemonicIn, pass *string) {
	var priv, pub *cryptopay.Key
	var err error
	var masterWIF, mnemonic string
	if *mnemonicIn == "" {
		priv, pub, mnemonic, err = cryptopay.NewMaster(*pass)
		if err != nil {
			panic(err)
		}
	} else {
		mnemonic = *mnemonicIn
		priv, pub, err = cryptopay.NewFromMnemonic(mnemonic, *pass)
		if err != nil {
			panic(err)
		}
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
	// master key/wallet
	masterWIF, err = priv.RootWIF()
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
