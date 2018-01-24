package cryptopay

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// https://github.com/ethereum/wiki/wiki/Design-Rationale#gas-and-fees
const GasLimit uint64 = 21000

// https://ethgasstation.info/
const GasPrice uint64 = 51 // 51 GWEI
const GweiToWei = 1000000000

func EstimateFee(c CoinType, tx []byte) (uint64, error) {
	switch c {
	case BTC:
		return uint64(1000 * len(tx)), nil // 1000 satoshi per byte
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
