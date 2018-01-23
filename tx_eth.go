package cryptopay

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	log "github.com/golang/glog"
	"math/big"
)

func MakeTransactionETH(fromKey *Key, to string, nonce uint64, value uint64, gasLimit, gasPrice uint64) ([]byte, error) {
	ecdsaKey, err := fromKey.ToECDSAPrivate()
	if err != nil {
		return nil, err
	}
	log.Errorf("  to %s, nonce %v, value %v, gasLimit %v, gasPrice %v", to, nonce, value, gasLimit, gasPrice)

	var amount = big.NewInt(int64(value))
	var gasPriceInt = big.NewInt(int64(gasPrice))
	toAddr := common.HexToAddress(to)

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
