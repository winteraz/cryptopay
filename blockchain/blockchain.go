package blockchain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/golang/glog"
	"github.com/winteraz/cryptopay"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	cl *http.Client
}

func New(cl *http.Client) *Client {
	return &Client{cl: cl}
}

type Output struct {
	Age           int    `json:"tx_age"`
	Hash          string `json:"tx_hash"`
	Index         uint32 `json:"tx_index"`
	N             int    `json:"tx_output_n"`
	Script        string `json:"script"`
	Value         uint64 `json:"value"`
	Confirmations int    `json:"confirmations"`
}

func (o *Output) ToUnspent() cryptopay.Unspent {
	return cryptopay.Unspent{
		Tx:            o.Hash,
		Index:         o.Index,
		Amount:        o.Value,
		Confirmations: o.Confirmations,
		Script:        o.Script,
	}
}

type Unspent struct {
	UnspentOutputs []Output `json:"unspent_output"`
}

// Implement wallet.Unspender. It supports bitcoin only
// receives xpub
func (c *Client) Unspent(cx context.Context, coin cryptopay.CoinType, addr ...string) (map[string][]cryptopay.Unspent, error) {
	if coin != cryptopay.BTC {
		return nil, errors.New("Only bitcoin is supported")
	}
	m := make(map[string][]cryptopay.Unspent)
	for _, address := range addr {
		URL := "https://blockchain.info/unspent?active=" + address
		req, err := http.NewRequest("GET", URL, nil)
		if err != nil {
			return nil, err
		}
		rsp, err := c.cl.Do(req)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		b, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			rsp.Body.Close()
			return nil, err
		}
		rsp.Body.Close()
		if rsp.StatusCode > 300 {
			if string(b) == "No free outputs to spend" {
				continue
			}
			err = fmt.Errorf("Invalid response: \n URL %s\n Status  %v, body %s",
				URL, rsp.StatusCode, b)
			log.Error(err)
			return nil, err
		}
		var v Unspent
		if err = json.Unmarshal(b, &v); err != nil {
			log.Errorf("%v, %s", err, b)
			return nil, err
		}
		for _, vv := range v.UnspentOutputs {
			m[address] = append(m[address], vv.ToUnspent())
		}
	}
	return m, nil
}

type Transactions struct {
	HASH         string        `json:"hash160"`
	Address      string        `json:"address"`
	NTX          int           `json:"n_tx"`
	NUnread      int           `json:"n_unredeemed"`
	Received     int           `json:"total_received"`
	Sent         int           `json: "total_sent"`
	Balance      int           `json:"final_balance"`
	Transactions []Transaction `json:"txs"`
}

type Transaction struct {
	TXID string `json:"txid"`
}

func (c *Client) HasTransactions(cx context.Context, coin cryptopay.CoinType, addr ...string) (map[string]bool, error) {
	if coin != cryptopay.BTC {
		return nil, errors.New("Only bitcoin is supported")
	}
	m := make(map[string]bool)
	for _, address := range addr {
		URL := "https://blockchain.info/rawaddr/" + address
		req, err := http.NewRequest("GET", URL, nil)
		if err != nil {
			return nil, err
		}
		rsp, err := c.cl.Do(req)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		b, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			rsp.Body.Close()
			return nil, err
		}
		rsp.Body.Close()
		if rsp.StatusCode > 300 {
			//if string(b) == "No free outputs to spend" {
			//	continue
			//}
			err = fmt.Errorf("Invalid response: \n URL %s\n Status  %v, body %s",
				URL, rsp.StatusCode, b)
			log.Error(err)
			return nil, err
		}
		var v Transactions
		if err = json.Unmarshal(b, &v); err != nil {
			log.Errorf("%v, %s", err, b)
			return nil, err
		}

		m[address] = (len(v.Transactions) > 0)
	}
	return m, nil
}

func (c *Client) BroadcastTX(cx context.Context, coin cryptopay.CoinType, tx []byte) error {
	const URL = "https://blockchain.info/pushtx"
	en := url.Values{}
	en.Set("tx", string(tx))
	req, err := http.NewRequest("POST", URL, strings.NewReader(en.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rsp, err := c.cl.Do(req)
	if err != nil {
		return err
	}
	rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return errors.New(rsp.Status)
	}
	return nil

}
