package main

import (
	"fmt"
	"github.com/winteraz/cryptopay"
)

func main() {
	k, err := cryptopay.NewMaster("somepass")
	if err != nil {
		panic(err)
	}
	mnemonic, err := k.Mnemonic()
	if err != nil {
		panic(err)
	}
	wif, err := k.WIF()
	if err != nil {
		panic(err)
	}
	fmt.Printf("mn %s \n, wif %s\n", mnemonic, wif)

}
