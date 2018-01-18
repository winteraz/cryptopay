package util

import (
	"context"
	"errors"
	log "github.com/golang/glog"
	"github.com/winteraz/cryptopay"
	"github.com/winteraz/cryptopay/blockchain"
	"github.com/winteraz/cryptopay/ethrpc"
	"github.com/winteraz/cryptopay/wallet"
	"net/http"
)

type Request struct {
	Mnemonic       string
	PrivKey        string
	Passwd         string
	ExtendedPublic string
	Coin           cryptopay.CoinType
}

func (r *Request) WalletAccount(cx context.Context, ethEndpointHost string, accountIndex uint32) (wallet.Wallet, error) {
	if r.Mnemonic == "" {
		return nil, errors.New("Invalid mnemonic")
	}
	var unspender wallet.Unspender
	switch r.Coin {
	case cryptopay.BTC:
		unspender = blockchain.New(http.DefaultClient)
	case cryptopay.ETH:
		if ethEndpointHost == "" {
			return nil, errors.New("Invalid ethEndpointHost")
		}
		ethEndpoint := "https://" + ethEndpointHost + ":8545"
		unspender = ethrpc.New(ethEndpoint, http.DefaultClient)
	default:
		return nil, errors.New("Invalid coin")
	}
	return wallet.FromMnemonic(r.Mnemonic, r.Passwd, unspender, r.Coin, accountIndex)

}

func (r *Request) PublicWallet(cx context.Context, ethEndpointHost string) (wallet.Wallet, error) {

	var unspender wallet.Unspender
	switch r.Coin {
	case cryptopay.BTC:
		unspender = blockchain.New(http.DefaultClient)
	case cryptopay.ETH:
		if ethEndpointHost == "" {
			return nil, errors.New("Invalid ethEndpointHost")
		}
		ethEndpoint := "https://" + ethEndpointHost + ":8545"
		unspender = ethrpc.New(ethEndpoint, http.DefaultClient)
	default:
		return nil, errors.New("Invalid coin")
	}
	if r.ExtendedPublic == "" {
		return nil, errors.New("no mnemonic or  ExtendedPublic")
	}
	return wallet.FromPublic(r.ExtendedPublic, r.Coin, unspender)
}

// returns map[coin]map[accountIndex][]transactionRaw
func (r *Request) MoveWallet(cx context.Context, ethEndpointHost string, toAddrPub string, accountsGap, addressGap uint32) (map[uint32][][]byte, error) {
	txaa := make(map[uint32][][]byte)
	for account := uint32(0); account <= accountsGap; account++ {
		w, err := r.WalletAccount(cx, ethEndpointHost, account)
		if err != nil {
			return nil, err
		}
		txa, err := w.Move(cx, toAddrPub, addressGap)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		if len(txa) == 0 {
			continue
		}
		txaa[account] = txa
		account = 0
	}
	return txaa, nil
}

// if Req doesn't have a private/key mnemonic the accountsGap is ignored(as we can't derivate account
// keys)

func (r *Request) Balance(cx context.Context, ethEndpointHost string, accountsGap, addressGap uint32) (ext, inter map[uint32]map[string]uint64, err error) {
	if r.Mnemonic == "" {
		// we use a dummy account b/c we don't know it
		const account = uint32(99999)
		w, err := r.PublicWallet(cx, ethEndpointHost)
		if err != nil {
			return nil, nil, err
		}
		var inter = make(map[uint32]map[string]uint64)
		var ext = make(map[uint32]map[string]uint64)
		extAcct, interAcct, err := accountBalance(cx, w, addressGap)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}
		if len(extAcct) != 0 {
			ext[account] = extAcct
		}
		if len(interAcct) != 0 {
			inter[account] = interAcct
		}
		return inter, ext, nil
	}
	return r.balanceAccounts(cx, ethEndpointHost, accountsGap, addressGap)
}

func (r *Request) balanceAccounts(cx context.Context, ethEndpointHost string, accountsGap, addressGap uint32) (ext, inter map[uint32]map[string]uint64, err error) {
	inter = make(map[uint32]map[string]uint64)
	ext = make(map[uint32]map[string]uint64)
	for account := uint32(0); account <= accountsGap; account++ {
		w, err := r.WalletAccount(cx, ethEndpointHost, account)
		if err != nil {
			return nil, nil, err
		}
		extAcct, interAcct, err := accountBalance(cx, w, addressGap)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}
		if len(extAcct) != 0 {
			ext[account] = extAcct
			account = 0
		}
		if len(interAcct) != 0 {
			inter[account] = interAcct
			account = 0
		}
	}
	return ext, inter, nil

}

func accountBalance(cx context.Context, w wallet.Wallet, addressGap uint32) (ext, inter map[string]uint64, err error) {
	kind := false
	ext, err = w.Balance(cx, kind, addressGap)
	if err != nil {
		return nil, nil, err
	}

	kind = true
	inter, err = w.Balance(cx, kind, addressGap)
	if err != nil {
		return nil, nil, err
	}
	return
}
