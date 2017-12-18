package main

import(
	"github.com/winteraz/cryptopay"
	"fmt"
)


func main(){
	mn, b58, err := cryptopay.NewMaster("javadog123")
	if err != nil{
		panic(err)
	}
	fmt.Printf("mn %s \n, b58 %s\n", mn, b58)

}