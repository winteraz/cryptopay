package wallet

import (
	"context"
	"errors"
	"github.com/winteraz/cryptopay"
)

// This actually works only for bitcoin at this time.
// If fee is zero it will try to guess the optimal fee.
// depth - level to lookup for addresses into wallet down the chain.
// accounts - number of accounts to look into for the "from" address.
func (w *wallet) MakeTransaction(cx context.Context, from, to string, coin cryptopay.CoinType, amount, fee uint64, accounts, depth uint32) ([]byte, error) {
	if w.priv == nil {
		return nil, errors.New("wallet is missing the private key")
	}
	if fee == 0 {
		return nil, errors.New("Transaction with fee zero can't be processed")
	}
	if w.priv == nil {
		return nil, errors.New("Wallet is missing a private key! Can't create transactions with public keys")
	}
	var priv string
	// find the private key for "From"
	for acct := uint32(0); acct <= accounts; acct++ {
		for dep := uint32(0); dep <= depth; dep++ {
			pub, err := w.priv.PublicAddr(coin, acct, dep)
			if err != nil {
				return nil, err
			}
			if pub != from {
				continue
			}
			priv, err = w.priv.PrivateKey(coin, acct, dep)
			if err != nil {
				return nil, err
			}
		}
	}
	if priv == "" {
		return nil, errors.New("'From'  was not found in the given wallet")
	}
	// make sure we have enough balance
	unspent, err := w.BalanceByAddress(cx, coin, from)
	if err != nil {
		return nil, err
	}
	if (amount + fee) > unspent {
		return nil, errors.New("Amount + fee is higher than the unspent amount")
	}
	unspentTX, err := w.unspender.Unspent(cx, coin, from)
	if err != nil {
		return nil, err
	}
	return cryptopay.MakeTransactionBTC(priv, to, amount, fee, unspentTX[from])
}

// Move the wallet to a different provider/address
// to - extended public keys where the payments are being transfered.
func (w *wallet) Move(cx context.Context, to map[cryptopay.CoinType]string) (map[cryptopay.CoinType][][]byte, error) {
	// The limits are reset after each positive result.
	const (
		accountsLimit uint32 = 20
		addressLimit  uint32 = 100
	)
	mp := make(map[cryptopay.CoinType][][]byte)
	for coin, toPub := range to {
		var acct uint32
		var acctIndex uint32
		for acct = 0; acct <= accountsLimit; acct++ {
			var addrDepth uint32
			var depth uint32
			for addrDepth = 0; addrDepth <= addressLimit; addrDepth++ {
				pub, err := w.priv.PublicAddr(coin, acctIndex, depth)
				if err != nil {
					return nil, err
				}

				amount, err := w.BalanceByAddress(cx, coin, pub)
				if err != nil {
					return nil, err
				}
				if amount < 1 {
					depth++
					acctIndex++
					continue
				}
				priv, err := w.priv.PrivateKey(coin, acctIndex, depth)
				k, err := cryptopay.ParseKey(toPub)
				if err != nil {
					return nil, err
				}
				index := uint32(len(mp))
				toAddr, err := k.DerivePublicAddr(coin, index)
				if err != nil {
					return nil, err
				}
				// Set an abritrary
				fee := uint64(1000)
				b, err := makeTransaction(cx, w.unspender, priv, pub, toAddr, coin, amount, fee)
				if err != nil {
					return nil, err
				}
				fee, err = cryptopay.EstimateFee(coin, b)
				if err != nil {
					return nil, err
				}
				amount = amount - fee
				if amount < 1 {
					continue
				}
				b, err = makeTransaction(cx, w.unspender, priv, pub, toAddr, coin, amount, fee)
				if err != nil {
					return nil, err
				}
				mp[coin] = append(mp[coin], b)
				depth = 0 // reset when we find a positive match.
				acctIndex = 0
			}
		}
	}
	return mp, nil
}

func makeTransaction(cx context.Context, unspender Unspender, priv, from, to string, coin cryptopay.CoinType, amount, fee uint64) ([]byte, error) {

	unspentTX, err := unspender.Unspent(cx, coin, from)
	if err != nil {
		return nil, err
	}
	return cryptopay.MakeTransactionBTC(priv, to, amount, fee, unspentTX[from])
}
