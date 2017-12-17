package cryptopay

import (

	"github.com/bartekn/go-bip39"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip32"



	log "github.com/golang/glog"
)

// receive base58 encoded public key and returns the bitcoin public address
func BTCAddr(pubKeyEncoded string) (string, error) {
	acct0Pub, err := hdkeychain.NewKeyFromString(pubKeyEncoded)
	if err != nil {
		return "", err
	}
	// m/49'/1'/0'/0
	acct0ExternalPub, err := acct0Pub.Child(0)
	if err != nil {
		return "", err
	}
	// bitcoin address 0
	// m/49'/1'/0'/0/0
	acct0External0Pub, err := acct0ExternalPub.Child(0)
	if err != nil {
		return "", err
	}
	// BIP49 segwit pay-to-script-hash style address.
	pubKey, err := acct0External0Pub.ECPubKey()
	if err != nil {
		return "", err
	}
	keyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	scriptSig, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(keyHash).Script()
	if err != nil {
		return "", err
	}
	acct0ExtAddr0, err := btcutil.NewAddressScriptHash(scriptSig, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}
	return acct0ExtAddr0.String(), nil

}


// returns a new masterkey along with its base58encoded form
func NewMaster(passw string)(mnemonic, b58 string, err error){
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Error(err)
		return
	}
	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		log.Error(err)
		return "", "", err
	}
	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed := bip39.NewSeed(mnemonic, "somepassword")
	// Create master private key from seed
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Error(err)
		return "", "", err
	}
	return mnemonic, masterKey.B58Serialize(), nil
}

type Key struct{
	Private, Public,  BTCPublic string
}

// receives a private (master key)
// returns a map private to public key base58 encoded
func DeriveKeys(masterKey string, startIndex, limit uint32)([]Key, error){
	masterK, err := bip32.Deserialize([]byte(masterKey))
	if err != nil{
		return nil, err
	}
	var keys []Key
	for i := startIndex; i <= startIndex+limit; i++ {
		k, err := masterK.NewChildKey(i)
		if err != nil {
			log.Error(err)
			continue
		}
		btcAddr, err :=  BTCAddr(k.PublicKey().B58Serialize())
		if err != nil {
			log.Error(err)
			return nil, err
		}
		key := Key{
			Private: k.B58Serialize(),
			Public:  k.PublicKey().B58Serialize(),
			BTCPublic: btcAddr, 
		}
		keys = append(keys, key)
	}
	return keys, nil
}