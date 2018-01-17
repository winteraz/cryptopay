package wallet

import (
	"context"
	"errors"
	"github.com/winteraz/cryptopay"
)

// This actually works only for bitcoin at this time.
// depth - level to lookup for addresses into wallet down the chain.
// accounts - number of accounts to look into for the "from" address.
func (w *wallet) MakeTransaction(cx context.Context, from, to string, amount, fee uint64, depth uint32) ([]byte, error) {
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

	for dep := uint32(0); dep <= depth; dep++ {
		var kind = false
		pub, err := w.pub.DeriveExtendedAddr(w.coin, kind, dep)
		if err != nil {
			return nil, err
		}
		if pub != from {
			kind = true
			pub, err := w.pub.DeriveExtendedAddr(w.coin, kind, dep)
			if err != nil {
				return nil, err
			}
			if pub != from {
				continue
			}
		}
		priv, err = w.priv.DeriveExtendedAddr(w.coin, kind, dep)
		if err != nil {
			return nil, err
		}
	}
	if priv == "" {
		return nil, errors.New("'From'  was not found in the given wallet")
	}
	// make sure we have enough balance
	unspent, err := w.BalanceByAddress(cx, from)
	if err != nil {
		return nil, err
	}
	if (amount + fee) > unspent {
		return nil, errors.New("Amount + fee is higher than the unspent amount")
	}
	unspentTX, err := w.unspender.Unspent(cx, from)
	if err != nil {
		return nil, err
	}
	return cryptopay.MakeTransactionBTC(priv, to, amount, fee, unspentTX[from])
}

func (w *wallet) DiscoverUsedIndex(cx context.Context, addressGap uint32) ([]uint32, error) {
	var mp []uint32
	const kind = false
	var addrDepth, depth uint32
	for addrDepth = 0; addrDepth <= addressGap; addrDepth++ {
		pub, err := w.pub.DeriveExtendedAddr(w.coin, kind, depth)
		if err != nil {
			return nil, err
		}
		ok, err := w.unspender.HasTransactions(cx, pub)
		if err != nil {
			return nil, err
		}

		if !ok[pub] {
			depth++
			continue
		}
		mp = append(mp, depth)
		addrDepth = 0 // reset when we find a positive match.
		depth++
	}
	return mp, nil
}

// returns a fresh external address
func (w *wallet) freshAddress(cx context.Context, exPub string) (string, error) {
	k, err := cryptopay.ParseKey(exPub)
	if err != nil {
		return "", err
	}
	const kind = false
	for i := uint32(0); i < 9999999; i++ {
		addr, err := k.DeriveExtendedAddr(w.coin, kind, i)
		if err != nil {
			return "", err
		}
		ok, err := w.unspender.HasTransactions(cx, addr)
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
// toPub - extended public keys where the payments are being transfered.
func (w *wallet) Move(cx context.Context, toPub string, addressGap uint32) ([][]byte, error) {
	// The limits are reset after each positive result.
	var mp [][]byte
	var unusedAddr string
	// find index of toPub
	addraIndex, err := w.DiscoverUsedIndex(cx, addressGap)
	if err != nil {
		return nil, err
	}
	for _, index := range addraIndex {
		var toAddr string
		if unusedAddr != "" {
			toAddr = unusedAddr
		} else {
			toAddr, err = w.freshAddress(cx, toPub)
			if err != nil {
				return nil, err
			}
		}
		kind := false
		b, err := w.withdrawAddress(cx, toAddr, kind, index)
		if err != nil {
			return nil, err
		}
		if b != nil {
			mp = append(mp, b)
			unusedAddr = ""
		}
		kind = true
		b, err = w.withdrawAddress(cx, toAddr, kind, index)
		if err != nil {
			return nil, err
		}
		if b == nil {
			continue
		}
		mp = append(mp, b)
		unusedAddr = ""
	}
	return mp, nil
}

func (w *wallet) withdrawAddress(cx context.Context, toAddr string, kind bool, index uint32) ([]byte, error) {
	pub, err := w.pub.DeriveExtendedAddr(w.coin, kind, index)
	if err != nil {
		return nil, err
	}
	amount, err := w.BalanceByAddress(cx, pub)
	if err != nil {
		return nil, err
	}
	if amount < 1 {
		return nil, nil
	}

	priv, err := w.priv.DeriveExtendedKey(kind, index)
	if err != nil {
		return nil, err
	}
	// Set an abritrary
	fee := uint64(1000)
	b, err := makeTransaction(cx, w.unspender, priv, pub, toAddr, w.coin, amount, fee)
	if err != nil {
		return nil, err
	}
	fee, err = cryptopay.EstimateFee(w.coin, b)
	if err != nil {
		return nil, err
	}
	if amount < (fee + 1) {
		return nil, nil
	}
	amount = amount - fee
	b, err = makeTransaction(cx, w.unspender, priv, pub, toAddr, w.coin, amount, fee)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func makeTransaction(cx context.Context, unspender Unspender, priv *cryptopay.Key, from, to string, coin cryptopay.CoinType, amount, fee uint64) ([]byte, error) {
	switch coin {
	case cryptopay.BTC:
		unspentTX, err := unspender.Unspent(cx, from)
		if err != nil {
			return nil, err
		}
		return cryptopay.MakeTransactionBTC(priv.Base58(), to, amount, fee, unspentTX[from])
	case cryptopay.ETH:
		nonceMap, err := unspender.CountTransactions(cx, from)
		if err != nil {
			return nil, err
		}
		nonce, ok := nonceMap[to]
		if !ok {
			return nil, errors.New("Unspender failed to return a nonce")
		}
		// https://github.com/ethereum/wiki/wiki/Design-Rationale#gas-and-fees
		const gasLimit uint64 = 21000
		// https://ethgasstation.info/
		const gasPrice uint64 = 51 // 51 GWEI
		return cryptopay.MakeTransactionETH(priv, from, to, nonce, amount, gasLimit, gasPrice)
	}
	return nil, errors.New("unsupported coin " + coin.String())
}
