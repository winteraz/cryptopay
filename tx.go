package cryptopay

import (
	"encoding/hex"
	"github.com/bitgoin/address"
	"github.com/bitgoin/tx"
)

type Unspent struct {
	Tx            string // hex encoded transaction
	Index         uint32 // transaction index
	Amount        uint64
	Confirmations int
	Script        string
}

// receives 'from' wiff encoded private key. and the BTC address to send.
func MakeTransactionBTC(from, to string, amount, fee uint64, unspent []Unspent) ([]byte, error) {
	coins, err := ToUTXO(unspent, from)
	if err != nil {
		return nil, err
	}
	//prepare send addresses and its amount.
	//last address must be refund address and its amount must be 0.
	send := []*tx.Send{
		&tx.Send{
			Addr:   to,
			Amount: amount,
		},
		&tx.Send{
			Addr:   "",
			Amount: 0,
		},
	}
	locktime := uint32(0)
	tx, err := tx.NewP2PK(fee, coins, locktime, send...)
	if err != nil {
		return nil, err
	}
	return tx.Pack()
}

// copy from https://github.com/bitgoin/blockr/blob/master/blockr.go#L171
//ToUTXO returns utxo in transaction package.
// privs bep58
func ToUTXO(utxos []Unspent, privs string) (tx.UTXOs, error) {
	//prepare private key.
	priv, err := address.FromWIF(privs, address.BitcoinMain)
	if err != nil {
		return nil, err
	}
	txs := make(tx.UTXOs, len(utxos))
	for i, utxo := range utxos {
		hash, err := hex.DecodeString(utxo.Tx)
		if err != nil {
			return nil, err
		}
		hash = tx.Reverse(hash)
		script, err := hex.DecodeString(utxo.Script)
		if err != nil {
			return nil, err
		}

		txs[i] = &tx.UTXO{
			Key:     priv,
			TxHash:  hash,
			TxIndex: utxo.Index,
			Script:  script,
		}
	}
	return txs, nil
}
