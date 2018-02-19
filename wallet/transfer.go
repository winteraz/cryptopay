package wallet

import (
	"context"
	"errors"
	log "github.com/golang/glog"
	"github.com/winteraz/cryptopay"
)

// discovers if there are transactions so that we can estimate the addressGap to follow.
// map[address]index
func (w *wallet) DiscoverUsedIndex(cx context.Context, kind bool, addressGap uint32, onlyOnce bool) ([]uint32, error) {
	// we set kind to false(external) b/c the internal address maps to the external one and
	//  external addreses can have internal (for change) but internal are more likely to be empty
	// if no chance was sent
	//kind = false // for some reasons this doesn't work...
	mp := []uint32{}
	var depth uint32
	for {
		var puba []string
		pubm := make(map[string]uint32)
		for addrDepth := uint32(0); addrDepth <= addressGap; addrDepth++ {
			pub, err := w.pub.DeriveExtendedAddr(w.coin, kind, depth)
			if err != nil {
				return nil, err
			}
			puba = append(puba, pub)
			pubm[pub] = depth
			depth++
		}
		addrOK, err := w.unspender.HasTransactions(cx, puba...)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		log.Infof("completed HasTransactions")
		var any bool
		for addr, ok := range addrOK {
			if !ok {
				continue
			}
			any = true
			index, ok := pubm[addr]
			if !ok {
				return nil, errors.New("Unspender returned an unknown address")
			}
			mp = append(mp, index)
		}
		if any == false || onlyOnce == true {
			// no address with transactions found
			break
		}
		log.Infof("depth %v has transactions ", depth)
	}
	return mp, nil
}

// returns a fresh external address
func freshAddress(cx context.Context, exPub string, coin cryptopay.CoinType, unspender Unspender) (string, error) {
	k, err := cryptopay.ParseKey(exPub)
	if err != nil {
		return "", err
	}
	const kind = false
	for i := uint32(0); i < 9999999; i++ {
		addr, err := k.DeriveExtendedAddr(coin, kind, i)
		if err != nil {
			return "", err
		}
		ok, err := unspender.HasTransactions(cx, addr)
		if err != nil {
			return "", err
		}
		if !ok[addr] {
			return addr, nil
		}
	}
	return "", errors.New("no address was found....impossible???")

}

type indexAmount struct {
	index  uint32
	kind   bool
	amount uint64
}

// returns map[index]amount
func (w *wallet) balanceByIndexes(cx context.Context, kind bool, addressGap uint32, onlyOnce bool) ([]indexAmount, uint32, error) {
	if addressGap == 0 {
		return nil, 0, errors.New("Invalid addressGap")
	}

	addraIndex, err := w.DiscoverUsedIndex(cx, kind, addressGap, onlyOnce)
	if err != nil {
		log.Error(err)
		return nil, 0, err
	}
	log.Infof("kind %v, addraIndex %#v", kind, addraIndex)
	if len(addraIndex) == 0 {
		return nil, 0, nil
	}
	var highIndex uint32
	// generate addresses from index
	mapByIndex := make(map[string]uint32)
	var addrs []string
	for _, depth := range addraIndex {
		if depth > highIndex {
			highIndex = depth
		}
		pub, err := w.pub.DeriveExtendedAddr(w.coin, kind, depth)
		if err != nil {
			return nil, 0, err
		}
		mapByIndex[pub] = depth
		addrs = append(addrs, pub)
	}
	addressAmountMap, err := w.BalanceByAddress(cx, addrs...)
	if err != nil {
		return nil, 0, err
	}
	var out []indexAmount
	for address, amount := range addressAmountMap {
		if amount < 1 {
			continue
		}
		log.Errorf("Address %s amount %v", address, amount)
		index, ok := mapByIndex[address]
		if !ok {
			return nil, 0, errors.New("Unexpected: balanceByIndexes - address index not found in address map")
		}
		out = append(out, indexAmount{index: index, kind: kind, amount: amount})
	}
	return out, highIndex, nil

}

// Move the wallet to a different provider/address
// toPub - extended public keys where the payments are being transfered.
func (w *wallet) Move(cx context.Context, toPub string, addressGap uint32) ([]string, error) {
	kind := false
	onlyOnce := false
	unspent, highestIndex, err := w.balanceByIndexes(cx, kind, addressGap, onlyOnce)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	if highestIndex == 0 && len(unspent) == 0 {
		return nil, nil
	}
	log.Infof("highest index is %v", highestIndex)
	kind = true
	onlyOnce = false
	unspentInt, _, err := w.balanceByIndexes(cx, kind, addressGap+highestIndex, onlyOnce)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	if len(unspentInt) > 0 {
		unspent = append(unspent, unspentInt...)
	}

	var mp []string
	var unusedAddr string
	for _, record := range unspent {
		var toAddr string
		if unusedAddr != "" {
			toAddr = unusedAddr
		} else {
			toAddr, err = freshAddress(cx, toPub, w.coin, w.unspender)
			if err != nil {
				log.Error(err)
				return nil, err
			}
		}
		b, err := w.withdrawAddress(cx, toAddr, record.kind, record.index, record.amount)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		if b == "" {
			continue
		}
		mp = append(mp, b)
		unusedAddr = ""
	}
	return mp, nil
}

func (w *wallet) withdrawAddress(cx context.Context, toAddr string, kind bool, index uint32, amount uint64) (string, error) {
	pub, err := w.pub.DeriveExtendedAddr(w.coin, kind, index)
	if err != nil {
		log.Error(err)
		return "", err
	}
	//log.Infof("pub is %v", pub)
	priv, err := w.priv.DeriveExtendedKey(kind, index)
	if err != nil {
		log.Error(err)
		return "", err
	}
	// Set an abritrary
	fee := uint64(1000)
	if amount < (fee + 1) {
		return "", nil
	}
	b, err := makeTransaction(cx, w.unspender, priv, pub, toAddr, w.coin, amount-fee, fee)
	if err != nil {
		log.Errorf("err %v, addr %v", err, pub)
		return "", err
	}
	fee, err = cryptopay.EstimateFee(w.coin, b)
	if err != nil {
		return "", err
	}
	if amount < (fee + 1) {
		log.Errorf("Amount %v is less than the fee %v", amount, fee+1)
		return "", nil
	}
	log.Infof("amount %v, fee %v, amount - fee %v", amount, fee, amount-fee)
	b, err = makeTransaction(cx, w.unspender, priv, pub, toAddr, w.coin, amount-fee, fee)
	if err != nil {
		return "", err
	}
	return cryptopay.EncodeRawTX(w.coin, b), nil
}

func makeTransaction(cx context.Context, unspender Unspender, priv *cryptopay.Key, from, to string, coin cryptopay.CoinType, amount, fee uint64) ([]byte, error) {
	privEnc, err := priv.PrivateRoot(coin)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	switch coin {
	case cryptopay.BTC:
		unspentTX, err := unspender.Unspent(cx, from)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		return cryptopay.MakeTransactionBTC(privEnc, to, amount, fee, unspentTX[from])
	case cryptopay.ETH:
		nonceMap, err := unspender.CountTransactions(cx, from)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		nonce, ok := nonceMap[from]
		if !ok {
			log.Errorf("nonceMap %q", nonceMap)
			return nil, errors.New("Unspender failed to return a nonce")
		}

		return cryptopay.MakeTransactionETH(priv, to, nonce, amount,
			cryptopay.GasLimit,
			cryptopay.GasPrice*cryptopay.GweiToWei)
	}
	return nil, errors.New("unsupported coin " + coin.String())
}
