// https://github.com/bitpay/insight-api
package btcrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/golang/glog"
	"github.com/winteraz/cryptopay"
	"io/ioutil"
	"net/http"
	"time"
	"strings"
)

type Client struct {
	endpoint string
	cl       *http.Client
}

func (c *Client)Do(req *http.Request)([]byte, int, error){
	rsp, err := c.cl.Do(req)
	if err != nil{
		return nil, 0, err
	}
	defer rsp.Body.Close()
	b, err := ioutil.ReadAll(rsp.Body)
	return b,  rsp.StatusCode, err
}

func New(endpoint string, cl *http.Client) *Client {
	return &Client{cl: cl, endpoint: endpoint}
}

type Output struct {
	Address       string `json:"address"` // the requested address
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

const timeout = 30 * time.Second
// Implement wallet.Unspender. It supports bitcoin only
// receives xpub
func (c *Client) Unspent(cx context.Context, addr ...string) (map[string][]cryptopay.Unspent, error) {
	if len(addr) == 0{
		return nil, errors.New("Invalid address list")
	}
	m := make(map[string][]cryptopay.Unspent)
	var addrs string
	if len(addr) == 1 {
		addrs = addr[0]
	} else {
		addrs = strings.Join(addr, ",")
	}
	if addrs == "" {
		return nil, fmt.Errorf("Invalid address list %q", addr)
	}
	URL := fmt.Sprintf("%s/insight-api/addrs/%s/utxo", c.endpoint, addrs)
	log.Infof("URL %s", URL)
	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, err
	}
	ctx, _ := context.WithTimeout(cx, timeout)
	req = req.WithContext(ctx)
	b, status, err := c.Do(req)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	if status != 200 {
		err = fmt.Errorf("Invalid response: \n URL %s\n Status  %v, body %s",
			URL, status, b)
		log.Error(err)
		return nil, err
	}
	var v []Output
	if err = json.Unmarshal(b, &v); err != nil {
		log.Errorf("%v, %s", err, b)
		return nil, err
	}
	for _, vv := range v {
		if vv.Address == "" {
			log.Errorf("%s", b)
			return nil, errors.New("Invalid address")
		}
		m[vv.Address] = append(m[vv.Address], vv.ToUnspent())
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
	if len(addr) == 0{
		return nil, errors.New("Invalid address list")
	}
	type Response struct {
		TotalItems int `json:"totalItems"`
	}
	type Rsp struct {
		address string
		ok      bool
		err     error
	}
	ch := make(chan Rsp, len(addr))
	m := make(map[string]bool)
	for _, address := range addr {
		go func(address string) {
			rsp := Rsp{address: address}
			URL := fmt.Sprintf("%s/insight-api/addrs/%s/txs?from=0&to=1", c.endpoint, address)
			var req *http.Request
			req, rsp.err = http.NewRequest("GET", URL, nil)
			if rsp.err != nil {
				ch <- rsp
				return
			}
			ctx, _ := context.WithTimeout(cx, timeout)
			req = req.WithContext(ctx)
			var b []byte
			var status int
			//log.Infof("StartTX call %s", URL)
			b, status, rsp.err = c.Do(req)
			if rsp.err != nil {
				log.Error(rsp.err)
				ch <- rsp
				return
			} 
			if status != 200 {
				rsp.err = fmt.Errorf("Invalid response: \n URL %s\n Status  %v, body %s",
					URL, status, b)
				log.Error(rsp.err)
				ch <- rsp
				return
			}
			var v Response
			if rsp.err = json.Unmarshal(b, &v); rsp.err != nil {
				log.Errorf("%v, %s", rsp.err, b)
				ch <- rsp
				return
			}

			rsp.ok = (v.TotalItems > 0)
			ch <- rsp
		}(address)
	}
	var i int
	for rsp := range ch {
		if rsp.err != nil {
			log.Error(rsp.err)
			return nil, rsp.err
		}
		m[rsp.address] = rsp.ok
		//log.Infof("address %s, ok %v", rsp.address, rsp.ok)
		if len(m) == len(addr){
			break
		}
		i++
	}
	close(ch)
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
	ctx, _ := context.WithTimeout(cx, timeout)
	req = req.WithContext(ctx)
	b, status, err := c.Do(req)
	if err != nil {
		return err
	}
 
	if status  != 200 {
		return fmt.Errorf("Status %s, body %s", status, b)
	}
	return nil

}
