// https://github.com/bitpay/insight-api
package btrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/golang/glog"
	"github.com/winteraz/cryptopay"
	"io/ioutil"
	"net/http"
	"strings"
)

type Client struct {
	endpoint string
	cl       *http.Client
}

func New(endpoint string, cl *http.Client) *Client {
	return &Client{cl: cl, endpoint: endpoint}
}

type Output struct {
	Hash          string `json:"txid"`
	N             int    `json:"vout"`
	Script        string `json:"scriptPubKey"`
	Satoshis      uint64 `json:"satoshis"`
	Confirmations int    `json:"confirmations"`
}

func (o *Output) ToUnspent() cryptopay.Unspent {
	return cryptopay.Unspent{
		Tx:            o.Hash,
		N:             uint32(o.N),
		Amount:        o.Satoshis,
		Confirmations: o.Confirmations,
		Script:        o.Script,
	}
}

// Implement wallet.Unspender. It supports bitcoin only
// receives xpub
func (c *Client) Unspent(cx context.Context, addr ...string) (map[string][]cryptopay.Unspent, error) {
	m := make(map[string][]cryptopay.Unspent)
	for _, address := range addr {
		URL := fmt.Sprintf("%s/insight-api/addr/%s/utxo", c.endpoint, address)
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
		rsp.Body.Close()
		if err != nil {
			return nil, err
		}
		if rsp.StatusCode != 200 {
			err = fmt.Errorf("Invalid response: \n URL %s\n Status  %v, body %s",
				URL, rsp.StatusCode, b)
			log.Error(err)
			return nil, err
		}
		var v []Output
		if err = json.Unmarshal(b, &v); err != nil {
			log.Errorf("%v, %s", err, b)
			return nil, err
		}
		for _, vv := range v {
			m[address] = append(m[address], vv.ToUnspent())
		}
	}
	return m, nil
}

func (c *Client) CountTransactions(cx context.Context, addr ...string) (map[string]uint64, error) {
	return nil, errors.New("Not implemented")
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

func (c *Client) HasTransactions(cx context.Context, addr ...string) (map[string]bool, error) {
	type Response struct {
		TotalItems int `json:"totalItems"`
	}
	m := make(map[string]bool)
	for _, address := range addr {
		URL := fmt.Sprintf("%s/insight-api/txs/?address=%s", c.endpoint, address)
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
		rsp.Body.Close()
		if err != nil {
			return nil, err
		}
		if rsp.StatusCode != 200 {
			err = fmt.Errorf("Invalid response: \n URL %s\n Status  %v, body %s",
				URL, rsp.StatusCode, b)
			log.Error(err)
			return nil, err
		}
		var v Response
		if err = json.Unmarshal(b, &v); err != nil {
			log.Errorf("%v, %s", err, b)
			return nil, err
		}
		m[address] = (v.TotalItems > 0)
	}
	return m, nil
}

func (c *Client) BroadcastTX(cx context.Context, coin cryptopay.CoinType, tx string) error {
	URL := fmt.Sprintf("%s/insight-api/tx/send", c.endpoint)
	type Req struct {
		RAWTX string `json:"rawtx"`
	}
	rb, err := json.Marshal(&Req{RAWTX: tx})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", URL, strings.NewReader(string(rb)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	rsp, err := c.cl.Do(req)
	if err != nil {
		return err
	}
	b, err := ioutil.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return fmt.Errorf("Status %s, body %s", rsp.Status, b)
	}
	return nil

}
