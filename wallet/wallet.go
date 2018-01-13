package cryptopay

import (
	"context"
	"errors"
	"github.com/winteraz/cryptopay"
)

type Unspender interface {
	Unspent(addr string) ([]cryptopay.Unspent, error)
}

func FromMnemonic(mnemonic, passwd string, unspender Unspender) (Wallet, error) {
	// Check if the key is private or public.
	private, public, err := cryptopay.NewFromMnemonic(mnemonic, passwd)
	if err != nil {
		return nil, err
	}
	return &wallet{priv: private, pub: public, unspender: unspender}, nil
}

func FromPublic(mnemonic string, unspender Unspender) (Wallet, error) {
	// Check if the key is private or public.
	return nil, nil
}

type Transaction struct {
	From, To      string
	Amount        uint64
	Confirmations int
	Fee           int64 //??
}

type Wallet interface {
	// depth How many addresses we should generate
	// returns map[address]balance.
	Balance(cx context.Context, coin cryptopay.CoinType, depth uint32) (map[string]uint64, error)
	BalanceByAddress(cx context.Context, coin cryptopay.CoinType, address string) (uint64, error)
	MakeTransaction(cx context.Context, from, to string, typ cryptopay.CoinType, amount, fee uint64, depth uint32) ([]byte, error)
	Transactions(cx context.Context, typ cryptopay.CoinType, depth uint32) ([]Transaction, error)
}

type wallet struct {
	unspender Unspender
	priv, pub *cryptopay.Key
}

func (w *wallet) Balance(cx context.Context, coin cryptopay.CoinType, depth uint32) (map[string]uint64, error) {
	account := uint32(0)
	out := make(map[string]uint64)
	for index := uint32(0); index <= depth; index++ {
		// generate addresses
		childPublic, err := w.pub.PublicAddr(coin, account, index)
		if err != nil {
			return nil, err
		}
		out[childPublic], err = w.BalanceByAddress(cx, coin, childPublic)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (w *wallet) BalanceByAddress(cx context.Context, coin cryptopay.CoinType, address string) (uint64, error) {
	// Get the balance
	unspent, err := w.unspender.Unspent(address)
	if err != nil {
		return 0, err
	}
	var amount uint64
	for _, un := range unspent {
		if un.Confirmations == 0 {
			continue
		}
		amount += un.Amount
	}
	return amount, nil
}

var DefaultDepth = uint32(999)

// This actually works only for bitcoin at this time.
// If fee is zero it will try to guess the optimal fee.
// depth - level to lookup for addresses into wallet down the chain.
func (w *wallet) MakeTransaction(cx context.Context, from, to string, coin cryptopay.CoinType, amount, fee uint64, depth uint32) ([]byte, error) {
	if fee == 0 {
		return nil, errors.New("Transaction with fee zero can't be processed")
	}
	if w.priv == nil {
		return nil, errors.New("Wallet is missing a private key! Can't create transactions with public keys")
	}
	// find the private key for "From"
	account := uint32(0)
	var priv string
	var pub string
	var err error
	for index := uint32(0); index <= depth; index++ {
		// generate addresses
		pub, err = w.pub.PublicAddr(coin, account, index)
		if err != nil {
			return nil, err
		}
		if pub != from {
			continue
		}
		priv, err = w.priv.PrivateKey(coin, account, index)
		if err != nil {
			return nil, err
		}
	}
	if priv == "" {
		return nil, errors.New("'From'  was not found in the given wallet")
	}
	// make sure we have enough balance
	unspent, err := w.BalanceByAddress(cx, coin, pub)
	if err != nil {
		return nil, err
	}
	if (amount + fee) > unspent {
		return nil, errors.New("Amount + fee is higher than the unspent amount")
	}
	unspentTX, err := w.unspender.Unspent(pub)
	if err != nil {
		return nil, err
	}
	return cryptopay.MakeTransactionBTC(priv, to, amount, fee, unspentTX)
}

// Bug: currently it only includes unspent transaction
// TODO: include spent transactions.
func (w *wallet) Transactions(cx context.Context, coinType cryptopay.CoinType, depth uint32) ([]Transaction, error) {
	return nil, errors.New("Not implemented")
}
