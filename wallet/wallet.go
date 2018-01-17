package wallet

import (
	"context"
	"errors"
	"github.com/winteraz/cryptopay"
)

type Unspender interface {
	HasTransactions(cx context.Context, addr ...string) (map[string]bool, error)
	Unspent(cx context.Context, addr ...string) (map[string][]cryptopay.Unspent, error)
	CountTransactions(cx context.Context, addr ...string) (map[string]uint64, error)
}

// from hardened public key(m/44/coin/account). This wallet is unable to sign transactions.
// receives a map[coin]map[account]Extended public key
func FromPublic(pub string, coin cryptopay.CoinType, unspender Unspender) (Wallet, error) {
	if len(pub) == 0 {
		return nil, errors.New("Invalid pub/empty")
	}
	k, err := cryptopay.ParseKey(pub)
	if err != nil {
		return nil, err
	}
	return &wallet{pub: k, coin: coin, unspender: unspender}, nil
}

func FromMnemonic(mnemonic, passwd string, unspender Unspender, coin cryptopay.CoinType, account uint32) (Wallet, error) {
	// Check if the key is private or public.
	private, _, err := cryptopay.NewFromMnemonic(mnemonic, passwd)
	if err != nil {
		return nil, err
	}
	accountExtededPrivate, err := private.DeriveExtendedAccountKey(true, coin, account)
	if err != nil {
		return nil, err
	}
	accountExtededPrivatePublic, err := private.DeriveExtendedAccountKey(false, coin, account)
	if err != nil {
		return nil, err
	}
	return &wallet{coin: coin,
		priv:      accountExtededPrivate,
		pub:       accountExtededPrivatePublic,
		unspender: unspender}, nil
}

type Transaction struct {
	From, To      string
	Amount        uint64
	Confirmations int
	Fee           int64 //??
}

type Wallet interface {
	Addresses(cx context.Context, kind bool, limit uint32) ([]string, error)
	// depth How many addresses we should generate
	// returns map[address]balance.
	Balance(cx context.Context, kind bool, depth uint32) (map[string]uint64, error)
	BalanceByAddress(cx context.Context, address string) (uint64, error)
	MakeTransaction(cx context.Context, from, to string, amount, fee uint64, addrDepth uint32) ([]byte, error)
	Move(cx context.Context, to string, addressGap uint32) ([][]byte, error)
	Transactions(cx context.Context, depth uint32) ([]Transaction, error)
}

type wallet struct {
	coin      cryptopay.CoinType
	unspender Unspender
	priv      *cryptopay.Key
	// hardened public key of bip 44/coin/accountIndex path.
	pub *cryptopay.Key
}

func (w *wallet) Addresses(cx context.Context, kind bool, limit uint32) ([]string, error) {
	var sa []string
	for index := uint32(0); index <= limit; index++ {
		// generate addresses
		// if we have a private key we can generate them directly for any coin
		if w.priv != nil {
			childPublic, err := w.pub.DeriveExtendedAddr(w.coin, kind, index)
			if err != nil {
				return nil, err
			}
			sa = append(sa, childPublic)
			continue
		}
		// otherwise we need to have them already generated (per account/coin).
		// This is due the fact bip-44 are hardened up to the account level so we can't use
		// a root key to generate count/account chains.
		if w.pub == nil {
			return nil, errors.New("we have no public key for the given coin and account index")
		}

		childPublic, err := w.pub.DeriveExtendedAddr(w.coin, kind, index)
		if err != nil {
			return nil, err
		}
		sa = append(sa, childPublic)
	}
	return sa, nil
}

func (w *wallet) Balance(cx context.Context, kind bool, depth uint32) (map[string]uint64, error) {
	out := make(map[string]uint64)

	// generate addresses
	addra, err := w.Addresses(cx, kind, depth)
	if err != nil {
		return nil, err
	}
	for _, addr := range addra {
		out[addr], err = w.BalanceByAddress(cx, addr)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (w *wallet) BalanceByAddress(cx context.Context, address string) (uint64, error) {
	// Get the balance
	unspent, err := w.unspender.Unspent(cx, address)
	if err != nil {
		return 0, err
	}
	var amount uint64
	for _, un := range unspent[address] {
		if un.Confirmations == 0 {
			continue
		}
		amount += un.Amount
	}
	return amount, nil
}

// Bug: currently it only includes unspent transaction
// TODO: include spent transactions.
func (w *wallet) Transactions(cx context.Context, depth uint32) ([]Transaction, error) {
	return nil, errors.New("Not implemented")
}
