package cryptopay

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	log "github.com/golang/glog"
	"math/big"
	"time"
)

func MakeTransactionETH(fromKey *Key, to string, nonce uint64, value uint64, gasLimit, gasPrice uint64) ([]byte, error) {
	t := time.Now()
	ecdsaKey, err := fromKey.ToECDSAPrivate()
	if err != nil {
		return nil, err
	}
	log.Errorf("  to %s, nonce %v, value %v, gasLimit %v, gasPrice %v", to, nonce, value, gasLimit, gasPrice)

	var amount = big.NewInt(int64(value))
	var gasPriceInt = big.NewInt(int64(gasPrice))
	toAddr := common.HexToAddress(to)

	// https://ethereum.stackexchange.com/questions/11551/what-are-the-ids-for-the-various-ethereum-chains
	chainID := big.NewInt(1)
	signer := types.NewEIP155Signer(chainID)
	log.Infof("Time since %s", time.Since(t))
	tx := types.NewTransaction(nonce, toAddr, amount, gasLimit, gasPriceInt, nil)
	log.Infof("Time since %s", time.Since(t))
	signedTx, err := types.SignTx(tx, signer, ecdsaKey)
	if err != nil {
		return nil, err
	}
	log.Infof("Time since %s", time.Since(t))
	var buff bytes.Buffer
	if err = signedTx.EncodeRLP(&buff); err != nil {
		return nil, err
	}
	log.Infof("Time since %s", time.Since(t))
	log.Flush()
	return buff.Bytes(), nil
}
