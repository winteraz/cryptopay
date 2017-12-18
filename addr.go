package cryptopay

import (
	"github.com/bartekn/go-bip39"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip32"

	"crypto/ecdsa"
	"fmt"
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
func NewMaster(passw string) (*Key, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return NewFromMnemonic(mnemonic, passw)
}

func NewFromMnemonic(mnemonic, passw string) (*Key, error) {
	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed := bip39.NewSeed(mnemonic, passw)
	// Create master private key from seed
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	k := &Key{k: masterKey, mnemonic: mnemonic, private: true}
	return k, nil
}

func (k *Key) Mnemonic() (string, error) {
	if k.mnemonic == "" {
		return "", fmt.Errorf("no mnemonic available")
	}
	return k.mnemonic, nil
}

func (k *Key) PrivateECDSA() (*ecdsa.PrivateKey, error) {
	if k.private == false {
		return nil, fmt.Errorf("key is not private")
	}
	priv, err := k.Private()
	if err != nil {
		return nil, err
	}
	privKey, err := hdkeychain.NewKeyFromString(priv)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	ecPriv, err := privKey.ECPrivKey()
	if err != nil {
		return nil, err
	}
	return ecPriv.ToECDSA(), nil
}

// creates the Wallet Import Format string encoding of a WIF structure.
func (k *Key) WIF() (string, error) {
	p, err := k.PrivateECDSA()
	if err != nil {
		return "", err
	}
	compress := false //?
	wf, err := btcutil.NewWIF((*btcec.PrivateKey)(p), &chaincfg.MainNetParams, compress)
	if err != nil {
		return "", err
	}
	return wf.String(), nil
}

// base 58
func (k *Key) Private() (string, error) {
	if !k.private {
		return "", fmt.Errorf("key is not private")
	}
	return k.k.B58Serialize(), nil
}

// base 58
func (k *Key) Public() (string, error) {
	return k.k.PublicKey().B58Serialize(), nil
}

func (k *Key) PublicBTC() (string, error) {
	return BTCAddr(k.k.PublicKey().B58Serialize())

}

type Key struct {
	private  bool
	k        *bip32.Key
	mnemonic string
}

// receives a private (master key)
// returns a map private to public key base58 encoded
func DeriveKeys(masterKey string, startIndex, limit uint32) ([]Key, error) {
	masterK, err := bip32.Deserialize([]byte(masterKey))
	if err != nil {
		return nil, err
	}
	var keys []Key
	for i := startIndex; i <= startIndex+limit; i++ {
		k, err := masterK.NewChildKey(i)
		if err != nil {
			log.Error(err)
			continue
		}

		key := Key{private: true, k: k}
		keys = append(keys, key)
	}
	return keys, nil
}
