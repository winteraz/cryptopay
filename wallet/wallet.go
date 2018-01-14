package wallet

import (
	"context"
	"errors"
	"github.com/winteraz/cryptopay"
)

type Unspender interface {
	Unspent(addr string) ([]cryptopay.Unspent, error)
}

// from hardened public key(m/44/coin/account). This wallet is unable to sign transactions.
func FromPublic(pub map[cryptopay.CoinType]map[uint32]string) (Wallet, error) {
	if pub == nil || len(pub) == 0 {
		return nil, errors.New("Invalid pub/empty")
	}
	pubKeyMap := make(map[cryptopay.CoinType]map[uint32]*cryptopay.Key)
	for coin, m := range pub {
		acctMap := make(map[uint32]*cryptopay.Key)

		for acctIndex, pubs := range m {
			k, err := cryptopay.ParseKey(pubs)
			if err != nil {
				return nil, err
			}
			acctMap[acctIndex] = k
		}
		pubKeyMap[coin] = acctMap
	}
	return &wallet{pub: pubKeyMap}, nil
}

func FromMnemonic(mnemonic, passwd string, unspender Unspender) (Wallet, error) {
	// Check if the key is private or public.
	private, _, err := cryptopay.NewFromMnemonic(mnemonic, passwd)
	if err != nil {
		return nil, err
	}
	return &wallet{priv: private, unspender: unspender}, nil
}

type Transaction struct {
	From, To      string
	Amount        uint64
	Confirmations int
	Fee           int64 //??
}

type Wallet interface {
	Addresses(cx context.Context, account, limit uint32, coin cryptopay.CoinType) ([]string, error)
	// depth How many addresses we should generate
	// returns map[address]balance.
	Balance(cx context.Context, account, depth uint32, coin ...cryptopay.CoinType) (map[cryptopay.CoinType]map[string]uint64, error)
	BalanceByAddress(cx context.Context, coin cryptopay.CoinType, address string) (uint64, error)
	MakeTransaction(cx context.Context, from, to string, typ cryptopay.CoinType, amount, fee uint64, acctDepth, addrDepth uint32) ([]byte, error)
	Transactions(cx context.Context, typ cryptopay.CoinType, depth uint32) ([]Transaction, error)
}

type wallet struct {
	unspender Unspender
	priv      *cryptopay.Key
	// hardened public key of bip 44/coin/accountIndex path.
	pub map[cryptopay.CoinType]map[uint32]*cryptopay.Key
}

func (w *wallet) Addresses(cx context.Context, account, limit uint32, coin cryptopay.CoinType) ([]string, error) {
	var sa []string
	for index := uint32(0); index <= limit; index++ {
		// generate addresses
		// if we have a private key we can generate them directly for any coin
		if w.priv != nil {
			childPublic, err := w.priv.PublicAddr(coin, account, index)
			if err != nil {
				return nil, err
			}
			sa = append(sa, childPublic)
			continue
		}
		// otherwise we need to have them already generated (per account/coin).
		// This is due the fact bip-44 are hardened up to the account level so we can't use
		// a root key to generate count/account chains.
		if w.pub == nil || w.pub[coin] == nil {
			return nil, errors.New("we have no public key for the given coin and account index")
		}
		k := w.pub[coin][account]
		if k == nil {
			return nil, errors.New("we have no public key for the given coin and account index")
		}
		childPublic, err := k.DerivePublicAddr(coin, index)
		if err != nil {
			return nil, err
		}
		sa = append(sa, childPublic)
	}
	return sa, nil
}

func (w *wallet) Balance(cx context.Context, account, depth uint32, coins ...cryptopay.CoinType) (map[cryptopay.CoinType]map[string]uint64, error) {
	out := make(map[string]uint64)
	cm := make(map[cryptopay.CoinType]map[string]uint64)
	for _, coin := range coins {
		// generate addresses
		addra, err := w.Addresses(cx, account, depth, coin)
		if err != nil {
			return nil, err
		}
		for _, addr := range addra {
			out[addr], err = w.BalanceByAddress(cx, coin, addr)
			if err != nil {
				return nil, err
			}
		}
		cm[coin] = out
	}
	return cm, nil
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

// Bug: currently it only includes unspent transaction
// TODO: include spent transactions.
func (w *wallet) Transactions(cx context.Context, coinType cryptopay.CoinType, depth uint32) ([]Transaction, error) {
	return nil, errors.New("Not implemented")
}
