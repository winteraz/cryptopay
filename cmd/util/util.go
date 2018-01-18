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
func (r *Request) MoveWallet(cx context.Context, ethEndpointHost string, toAddrPub string, accountGap, addressGap uint32) (map[uint32][][]byte, error) {
	txaa := make(map[uint32][][]byte)
	for account := uint32(0); account <= accountGap; account++ {
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

type Balance struct {
	Internal map[uint32]map[string]uint64
	External map[uint32]map[string]uint64
	Total    uint64
}

// if Req doesn't have a private/key mnemonic the accountsGap is ignored(as we can't derivate account
// keys)

func (r *Request) Balance(cx context.Context, ethEndpointHost string, accountsGap, addressGap uint32) (*Balance, error) {
	if r.Mnemonic == "" {
		// we use a dummy account b/c we don't know it
		const account = uint32(99999)
		w, err := r.PublicWallet(cx, ethEndpointHost)
		if err != nil {
			return nil, err
		}
		bal := &Balance{
			Internal: make(map[uint32]map[string]uint64),
			External: make(map[uint32]map[string]uint64),
		}
		extAcct, interAcct, err := accountBalance(cx, w, addressGap)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		if len(extAcct) != 0 {
			bal.External[account] = extAcct
		}
		if len(interAcct) != 0 {
			bal.Internal[account] = interAcct
		}
		for _, v := range extAcct {
			bal.Total += v
		}
		for _, v := range interAcct {
			bal.Total += v
		}

		return bal, nil
	}
	return r.balanceAccounts(cx, ethEndpointHost, accountsGap, addressGap)
}

func (r *Request) balanceAccounts(cx context.Context, ethEndpointHost string, accountsGap, addressGap uint32) (*Balance, error) {
	bal := &Balance{
		Internal: make(map[uint32]map[string]uint64),
		External: make(map[uint32]map[string]uint64),
	}
	accountIndex := uint32(0)
	for account := uint32(0); account <= accountsGap; account++ {
		w, err := r.WalletAccount(cx, ethEndpointHost, accountIndex)
		if err != nil {
			return nil, err
		}
		extAcct, interAcct, err := accountBalance(cx, w, addressGap)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		if len(extAcct) != 0 {
			bal.External[accountIndex] = extAcct
			account = 0
		}
		if len(interAcct) != 0 {
			bal.Internal[accountIndex] = interAcct
			account = 0
		}
		for _, v := range extAcct {
			bal.Total += v
		}
		for _, v := range interAcct {
			bal.Total += v
		}
		accountIndex++
	}
	return bal, nil

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
