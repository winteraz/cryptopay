package wallet

import (
	"context"
	"errors"
	"github.com/winteraz/cryptopay"
)

// This actually works only for bitcoin at this time.
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
			var kind = false
			pub, err := w.priv.PublicAddr(coin, acct, kind, dep)
			if err != nil {
				return nil, err
			}
			if pub != from {
				kind = true
				pub, err := w.priv.PublicAddr(coin, acct, kind, dep)
				if err != nil {
					return nil, err
				}
				if pub != from {
					continue
				}
			}
			priv, err = w.priv.PrivateKey(coin, acct, kind, dep)
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

type KeyIndex struct {
	Account, Address uint32
}

func (w *wallet) DiscoverUsedIndex(cx context.Context, accountsGap, addressGap uint32, coin cryptopay.CoinType) ([]KeyIndex, error) {
	var mp []KeyIndex
	var acct, acctIndex uint32
	const kind = false
	for acct = 0; acct <= accountsGap; acct++ {
		var addrDepth, depth uint32
		for addrDepth = 0; addrDepth <= addressGap; addrDepth++ {
			pub, err := w.priv.PublicAddr(coin, acctIndex, kind, depth)
			if err != nil {
				return nil, err
			}
			ok, err := w.unspender.HasTransactions(cx, coin, pub)
			if err != nil {
				return nil, err
			}

			if !ok[pub] {
				depth++
				continue
			}
			mp = append(mp, KeyIndex{Account: acctIndex, Address: depth})
			addrDepth = 0 // reset when we find a positive match.
			acct = 0
			depth++
		}
		acctIndex++
	}
	return mp, nil
}

// returns a fresh external address
func (w *wallet) freshAddress(cx context.Context, coin cryptopay.CoinType, exPub string) (string, error) {
	k, err := cryptopay.ParseKey(exPub)
	if err != nil {
		return "", err
	}
	const kind = false
	for i := uint32(0); i < 9999999; i++ {
		addr, err := k.DerivePublicAddr(coin, kind, i)
		if err != nil {
			return "", err
		}
		ok, err := w.unspender.HasTransactions(cx, coin, addr)
		if err != nil {
			return "", err
		}
		if !ok[addr] {
			return addr, nil
		}
	}
	return "", errors.New("no address was found....impossible???")

}

// Move the wallet to a different provider/address
// to - extended public keys where the payments are being transfered.
func (w *wallet) Move(cx context.Context, to map[cryptopay.CoinType]string, accountsGap, addressGap uint32) (map[cryptopay.CoinType][][]byte, error) {

	// The limits are reset after each positive result.
	mp := make(map[cryptopay.CoinType][][]byte)
	for coin, toPub := range to {
		var unusedAddr string
		// find index of toPub
		addraIndex, err := w.DiscoverUsedIndex(cx, accountsGap, addressGap, coin)
		if err != nil {
			return nil, err
		}
		for _, index := range addraIndex {
			var toAddr string
			if unusedAddr != "" {
				toAddr = unusedAddr
			} else {
				toAddr, err = w.freshAddress(cx, coin, toPub)
				if err != nil {
					return nil, err
				}
			}
			kind := false
			b, err := w.withdrawAddress(cx, toAddr, coin, kind, index)
			if err != nil {
				return nil, err
			}
			if b != nil {
				mp[coin] = append(mp[coin], b)
				unusedAddr = ""
			}
			kind = true
			b, err = w.withdrawAddress(cx, toAddr, coin, kind, index)
			if err != nil {
				return nil, err
			}
			if b == nil {
				continue
			}
			mp[coin] = append(mp[coin], b)
			unusedAddr = ""
		}
	}
	return mp, nil
}

func (w *wallet) withdrawAddress(cx context.Context, toAddr string, coin cryptopay.CoinType, kind bool, index KeyIndex) ([]byte, error) {
	pub, err := w.priv.PublicAddr(coin, index.Account, kind, index.Address)
	if err != nil {
		return nil, err
	}
	amount, err := w.BalanceByAddress(cx, coin, pub)
	if err != nil {
		return nil, err
	}
	if amount < 1 {
		return nil, nil
	}

	priv, err := w.priv.PrivateKey(coin, index.Account, kind, index.Address)
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
	if amount < (fee + 1) {
		return nil, nil
	}
	amount = amount - fee
	b, err = makeTransaction(cx, w.unspender, priv, pub, toAddr, coin, amount, fee)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func makeTransaction(cx context.Context, unspender Unspender, priv, from, to string, coin cryptopay.CoinType, amount, fee uint64) ([]byte, error) {

	unspentTX, err := unspender.Unspent(cx, coin, from)
	if err != nil {
		return nil, err
	}
	return cryptopay.MakeTransactionBTC(priv, to, amount, fee, unspentTX[from])
}
