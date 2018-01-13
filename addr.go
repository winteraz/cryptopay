package cryptopay

import (
	"encoding/hex"
	"fmt"
	"github.com/bartekn/go-bip39"
	"github.com/btcsuite/btcd/chaincfg"
	// "github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/crypto"
	log "github.com/golang/glog"
)

// returns a new masterkey along with its base58encoded form
func NewMaster(passw string) (private, public *Key, mnemonic string, err error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Error(err)
		return nil, nil, "", err
	}
	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		log.Error(err)
		return nil, nil, "", err
	}
	private, public, err = NewFromMnemonic(mnemonic, passw)
	return
}

func NewFromMnemonic(mnemonic, passw string) (private, public *Key, err error) {
	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed := bip39.NewSeed(mnemonic, passw)
	// Create master private key from seed
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, nil, err
	}
	private = (*Key)(master)
	neut, err := master.Neuter()
	if err != nil {
		return nil, nil, err
	}
	public = (*Key)(neut)
	return private, public, nil
}

// Encodes the extended key into base58. It's recommended to use this format
// for root keys only.
func (k *Key) Base58() string {
	return (*hdkeychain.ExtendedKey)(k).String()
}

// parse the base58 encoded key
func ParseKey(k string) (*Key, error) {
	ke, err := hdkeychain.NewKeyFromString(k)
	if err != nil {
		return nil, err
	}
	return (*Key)(ke), nil
}

func (k *Key) RootWIF() (string, error) {
	compress := true //?
	priv, err := (*hdkeychain.ExtendedKey)(k).ECPrivKey()
	if err != nil {
		return "", err
	}
	wf, err := btcutil.NewWIF(priv, &chaincfg.MainNetParams, compress)
	if err != nil {
		return "", err
	}
	return wf.String(), nil
}

func (k *Key) RootPrivateEIP55() (string, error) {
	return k.privateETH()

}
func (k *Key) RootPublicEIP55() (string, error) {
	return k.publicETHAddr()

}

// creates the Wallet Import Format string encoding of a WIF structure.
func (k *Key) WIF(coinTyp CoinType, account, index uint32) (string, error) {
	acctXExternalX, err := k.deriveKey(coinTyp, account, index)
	if err != nil {
		return "", err
	}
	return acctXExternalX.RootWIF()
}

// https://github.com/libbitcoin/libbitcoin/wiki/Altcoin-Version-Mappings
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
type CoinType uint32

const (
	BTC CoinType = 0
	BCH CoinType = 145
	ETH CoinType = 60
)

func (k *Key) deriveKey(coinTyp CoinType, account, index uint32) (*Key, error) {
	// m/49'
	purpose, err := (*hdkeychain.ExtendedKey)(k).Child(49)
	if err != nil {
		return nil, err
	}

	// m/49'/1'
	coinType, err := purpose.Child(uint32(coinTyp))
	if err != nil {
		return nil, err
	}

	// m/49'/1'/0'
	acctX, err := coinType.Child(account)
	if err != nil {
		return nil, err
	}
	// Derive the extended key for the account 0 external chain.  This
	// gives the path:
	//   m/0H/0
	// 0 is external, 1 is internal address (used for change, wallet software)
	// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
	acctXExt, err := acctX.Child(0)
	if err != nil {
		return nil, err
	}
	// Derive the Indexth extended key for the account X external chain.
	// m/49'/1'/0'/0
	acctXExternalX, err := acctXExt.Child(index)
	if err != nil {
		return nil, err
	}
	return (*Key)(acctXExternalX), nil
}

func (k *Key) PublicAddr(coinTyp CoinType, account, index uint32) (string, error) {
	acctXExternalX, err := k.deriveKey(coinTyp, account, index)
	if err != nil {
		log.Error(err)
		return "", err
	}
	switch coinTyp {
	case BTC, BCH:
		return acctXExternalX.publicBTCAddr()
	case ETH:
		return acctXExternalX.publicETHAddr()
	}
	return "", fmt.Errorf("Invalid coin type")
}

func (k Key) PrivateKey(coinTyp CoinType, account, index uint32) (string, error) {
	acctXExternalX, err := k.deriveKey(coinTyp, account, index)
	if err != nil {
		log.Error(err)
		return "", err
	}
	switch coinTyp {
	case BTC, BCH:
		return acctXExternalX.RootWIF()
	case ETH:
		return acctXExternalX.privateETH()
	}
	return "", fmt.Errorf("Invalid coin type")
}

func (k *Key) privateETH() (string, error) {
	priv, err := (*hdkeychain.ExtendedKey)(k).ECPrivKey()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.FromECDSA(priv.ToECDSA())), nil
}

// EIP55
func (k *Key) publicETHAddr() (string, error) {
	// EIP:
	pubKey, err := (*hdkeychain.ExtendedKey)(k).ECPubKey()
	if err != nil {
		return "", err
	}
	return crypto.PubkeyToAddress(*pubKey.ToECDSA()).Hex(), nil
}

func (k *Key) publicBTCAddr() (string, error) {

	pubKey, err := (*hdkeychain.ExtendedKey)(k).Address(&chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}
	return pubKey.EncodeAddress(), nil
	/*
		// BIP49 segwit pay-to-script-hash style address.
		pubKey, err := (*hdkeychain.ExtendedKey)(k).ECPubKey()
		if err != nil {
			return "", err
		}

		keyHash := btcutil.Hash160(pubKey.SerializeCompressed())
		scriptSig, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(keyHash).Script()
		if err != nil {
			return "", err
		}
		addr, err := btcutil.NewAddressScriptHash(scriptSig, &chaincfg.MainNetParams)
		if err != nil {
			return "", err
		}
		return addr.String(), nil
	*/
}

type Key hdkeychain.ExtendedKey

// receives the master public key (Neuster) and returns a list of addresses ?
func (masterPublicKey *Key) DeriveAddress(coin CoinType, account, startIndex, limit uint32) ([]string, error) {
	var keys []string
	for i := startIndex; i <= startIndex+limit; i++ {
		k, err := masterPublicKey.PublicAddr(coin, account, i)
		if err != nil {
			log.Error(err)
			continue
		}
		keys = append(keys, k)
	}
	return keys, nil
}
