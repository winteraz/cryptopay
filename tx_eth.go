package cryptopay

import (
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
)

func MakeTransactionETH(fromKey *Key, from, to string, nonce uint64, value uint64, gasLimit, gasPrice uint64) ([]byte, error) {
	ecdsaKey, err := fromKey.ToECDSAPrivate()
	if err != nil {
		return nil, err
	}

	var amount = big.NewInt(int64(value))
	var gasPriceInt = big.NewInt(int64(gasPrice))
	var bytesto [20]byte
	_bytesto, _ := hex.DecodeString(to[2:])
	copy(bytesto[:], _bytesto)
	toAddr := common.Address([20]byte(bytesto))

	var data []byte
	signer := types.NewEIP155Signer(nil)
	tx := types.NewTransaction(nonce, toAddr, amount, gasLimit, gasPriceInt, data)
	signed_tx, err := types.SignTx(tx, signer, ecdsaKey)
	if err != nil {
		return nil, err
	}

	ts := types.Transactions{signed_tx}
	return ts.GetRlp(0), nil
}
