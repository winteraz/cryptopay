package cryptopay

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	log "github.com/golang/glog"
	"math/big"
	"strings"
)

// https://github.com/ethereum/wiki/wiki/Design-Rationale#gas-and-fees
const GasLimit uint64 = 21000

// https://ethgasstation.info/
const GasPrice uint64 = 51 // 51 GWEI
const GweiToWei = 1000000000

func EstimateFee(c CoinType, tx []byte) (uint64, error) {
	switch c {
	case BTC:
		const fee = 130 // 1000 // satoshi per byte
		return uint64(fee * len(tx)), nil
	case ETH:
		return GasLimit * (GasPrice * GweiToWei), nil // Fee should be returned in Wei ?
	}
	return 0, errors.New("Not handled")
}

func EncodeRawTX(coin CoinType, raw []byte) string {
	switch coin {
	case BTC:
		return hex.EncodeToString(raw)
	case ETH:
		return fmt.Sprintf("0x%x", raw)
	}
	return "invalid coin"
}

type Transaction struct {
	Amount uint64
	To     string
}

func DecodeTX(coin CoinType, raw ...string) ([]Transaction, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid raw transaction/empty")
	}
	var ta []Transaction
	for _, tx := range raw {
		b, err := hex.DecodeString(strings.TrimPrefix(tx, "0x"))
		if err != nil {
			log.Errorf("tx %v, err %v", tx, err)
			return nil, err
		}
		switch coin {
		case BTC:
			tdx, err := btcutil.NewTxFromBytes(b)
			if err != nil {
				log.Error(err)
				return nil, err
			}
			if tdx.MsgTx() == nil {
				return nil, fmt.Errorf("Invalid MsgTX()")
			}
			out := tdx.MsgTx().TxOut
			if len(out) != 1 {
				err = fmt.Errorf("Invalid out %#v", out)
				return nil, err
			}
			if out[0].Value < 1 {
				err = fmt.Errorf("Invalid out amount %#v", out[0])
				log.Error(err)
				return nil, err
			}
			t := Transaction{Amount: uint64(out[0].Value), To: string(out[0].PkScript)}
			ta = append(ta, t)
		case ETH:
			r := rlp.NewStream(bytes.NewReader(b), 0)
			tr := new(types.Transaction)
			if err := tr.DecodeRLP(r); err != nil {
				return nil, err
			}
			chainID := big.NewInt(1)
			signer := types.NewEIP155Signer(chainID)
			msg, err := tr.AsMessage(signer)
			if err != nil {
				return nil, err
			}
			t := Transaction{
				To:     msg.To().String(),
				Amount: msg.Value().Uint64(),
			}
			ta = append(ta, t)
		default:
			return nil, errors.New("invalid coin")
		}
	}
	return ta, nil
}
