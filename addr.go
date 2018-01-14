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
	acctXExternalX, err := k.deriveKey(true, coinTyp, account, index)
	if err != nil {
		return "", err
	}
	return acctXExternalX.RootWIF()
}

// https://github.com/libbitcoin/libbitcoin/wiki/Altcoin-Version-Mappings
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
type CoinType uint32

func (c CoinType) String() string {
	switch c {
	case BTC:
		return "BTC"
	case BCH:
		return "BCH"
	case ETH:
		return "ETH"
	}
	return "invalid"
}

const (
	BTC CoinType = 0
	BCH CoinType = 145
	ETH CoinType = 60
)

// derives a bip-44 hardened key derived up to the account level(purpose/coint type/account)
// The public key may be used securely in non trusted environments to generate
// addresses for the given coin/account.
func (k *Key) deriveCoinKey(private bool, coinTyp CoinType, account uint32) (*Key, error) {
	// m/49'
	purpose, err := (*hdkeychain.ExtendedKey)(k).Child(44 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	// m/44'/0'
	coinType, err := purpose.Child(uint32(coinTyp) + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	// m/44'/0'/0'
	acctX, err := coinType.Child(account + hdkeychain.HardenedKeyStart)
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
	if !private {
		return (*Key)(acctXExt), nil
	}
	acctXExternalPub, err := acctXExt.Neuter()
	if err != nil {
		return nil, err
	}
	return (*Key)(acctXExternalPub), nil
}

func (k *Key) deriveKey(private bool, coinTyp CoinType, account, index uint32) (*Key, error) {
	acctXExternalPub, err := k.deriveCoinKey(private, coinTyp, account)
	if err != nil {
		return nil, err
	}
	// Derive the Indexth extended key for the account X external chain.
	// m/44'/0'/0'/0
	acctXExternalX, err := (*hdkeychain.ExtendedKey)(acctXExternalPub).Child(index)
	if err != nil {
		return nil, err
	}
	return (*Key)(acctXExternalX), nil
}

// k must be a hardened public key/Neuster
func (k *Key) DerivePublicAddr(coinTyp CoinType, index uint32) (string, error) {
	acctXExternalX, err := (*hdkeychain.ExtendedKey)(k).Child(index)
	if err != nil {
		return "", err
	}
	return (*Key)(acctXExternalX).PayAddress(coinTyp)
}

func (k *Key) PublicAddr(coinTyp CoinType, account, index uint32) (string, error) {
	acctXExternalX, err := k.deriveKey(false, coinTyp, account, index)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return (*Key)(acctXExternalX).PayAddress(coinTyp)
}

func (k *Key) PayAddress(coinTyp CoinType) (string, error) {
	switch coinTyp {
	case BTC, BCH:
		return k.publicBTCAddr()
	case ETH:
		return k.publicETHAddr()
	}
	return "", fmt.Errorf("Invalid coin type")

}

func (k Key) PrivateKey(coinTyp CoinType, account, index uint32) (string, error) {
	acctXExternalX, err := k.deriveKey(true, coinTyp, account, index)
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
