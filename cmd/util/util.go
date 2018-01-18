package util

import (
	"context"
	"errors"
	log "github.com/golang/glog"
	"github.com/winteraz/cryptopay"
	"github.com/winteraz/cryptopay/btcrpc"
	"github.com/winteraz/cryptopay/ethrpc"
	"github.com/winteraz/cryptopay/wallet"
	"net/http"
)

func newUnspender(remoteHost string, coin cryptopay.CoinType) (wallet.Unspender, error) {
	switch coin {
	case cryptopay.BTC:
		endpoint := "https://" + remoteHost + ":3001"
		return btrpc.New(endpoint, http.DefaultClient), nil
	case cryptopay.ETH:
		if remoteHost == "" {
			return nil, errors.New("Invalid remoteHost")
		}
		endpoint := "https://" + remoteHost + ":8545"
		return ethrpc.New(endpoint, http.DefaultClient), nil
	}
	return nil, errors.New("Invalid coin")

}

type Request struct {
	Mnemonic       string
	PrivKey        string
	Passwd         string
	ExtendedPublic string
	Coin           cryptopay.CoinType
}

func (r *Request) WalletAccount(cx context.Context, remoteHost string, accountIndex uint32) (wallet.Wallet, error) {
	if r.Mnemonic == "" {
		return nil, errors.New("Invalid mnemonic")
	}
	unspender, err := newUnspender(remoteHost, r.Coin)
	if err != nil {
		return nil, err
	}
	return wallet.FromMnemonic(r.Mnemonic, r.Passwd, unspender, r.Coin, accountIndex)

}

func (r *Request) PublicWallet(cx context.Context, remoteHost string) (wallet.Wallet, error) {

	unspender, err := newUnspender(remoteHost, r.Coin)
	if err != nil {
		return nil, err
	}
	if r.ExtendedPublic == "" {
		return nil, errors.New("no mnemonic or  ExtendedPublic")
	}
	return wallet.FromPublic(r.ExtendedPublic, r.Coin, unspender)
}

// returns  map[accountIndex][]transactionRaw
func (r *Request) MoveWallet(cx context.Context, remoteHost string, toAddrPub string, accountGap, addressGap uint32) (map[uint32][]string, error) {
	txaa := make(map[uint32][]string)
	accountIndex := uint32(0)
	for account := uint32(0); account <= accountGap; account++ {
		w, err := r.WalletAccount(cx, remoteHost, accountIndex)
		if err != nil {
			return nil, err
		}
		txa, err := w.Move(cx, toAddrPub, addressGap)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		if len(txa) == 0 {
			accountIndex++
			continue
		}
		txaa[accountIndex] = txa
		account = 0
		accountIndex++
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

func (r *Request) Balance(cx context.Context, remoteHost string, accountsGap, addressGap uint32) (*Balance, error) {
	if r.Mnemonic == "" {
		// we use a dummy account b/c we don't know it
		const account = uint32(99999)
		w, err := r.PublicWallet(cx, remoteHost)
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
	return r.balanceAccounts(cx, remoteHost, accountsGap, addressGap)
}

func (r *Request) balanceAccounts(cx context.Context, remoteHost string, accountsGap, addressGap uint32) (*Balance, error) {
	bal := &Balance{
		Internal: make(map[uint32]map[string]uint64),
		External: make(map[uint32]map[string]uint64),
	}
	accountIndex := uint32(0)
	for account := uint32(0); account <= accountsGap; account++ {
		w, err := r.WalletAccount(cx, remoteHost, accountIndex)
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
