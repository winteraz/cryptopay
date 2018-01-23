package ethrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/winteraz/cryptopay"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

/*https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gettransactioncount
// Request
curl -X POST --data '{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["0x407d73d8a49eeb85d32cf465507dd71d507100c1","latest"],"id":1}'

// Result
{
  "id":1,
  "jsonrpc": "2.0",
  "result": "0x1" // 1
}

*/

type Client struct {
	endpoint string
	client   *http.Client
}

func New(endpoint string, client *http.Client) *Client {

	return &Client{endpoint: endpoint, client: client}
}

type Result struct {
	ID      int    `json:"id"`
	Version string `json:"jsonrpc"`
	Result  string `json:"result"`
}

func (c *Client) CountTransactions(cx context.Context, addr ...string) (map[string]uint64, error) {
	if len(addr) == 0 {
		return nil, errors.New("Invalid address list")
	}
	type rsp struct {
		nonce   uint64
		address string
		err     error
	}
	ch := make(chan rsp, len(addr))
	for _, address := range addr {
		go func(address string) {
			v := rsp{address: address}
			v.nonce, v.err = c.CountTransactionsByAddress(cx, address)
			ch <- v
		}(address)
	}
	m := make(map[string]uint64)
	for v := range ch {
		if v.err != nil {
			return nil, v.err
		}
		m[v.address] = v.nonce
		if len(m) == len(addr) {
			break
		}
	}
	return m, nil
}

func (c *Client) CountTransactionsByAddress(cx context.Context, address string) (uint64, error) {

	const dataTpl = `{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["{{Address}}","latest"],"id":1}`
	data := strings.Replace(dataTpl, "{{Address}}", address, 1)
	b, err := c.makeReq(data)
	if err != nil {
		return 0, err
	}
	var v Result
	if err = json.Unmarshal(b, &v); err != nil {
		return 0, fmt.Errorf("Err %v, B %s", err, b)
	}
	lit := strings.TrimPrefix(v.Result, "0x")
	return strconv.ParseUint(lit, 16, 64)
}

func (c *Client) HasTransactions(cx context.Context, addr ...string) (map[string]bool, error) {
	// we use balance as there is nothing to be done with empty addresseses
	if len(addr) == 0 {
		return nil, errors.New("Invalid address list")
	}
	type Rsp struct {
		address string
		ok      bool
		err     error
	}
	amountMap, err := c.Balance(addr...)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool)
	for address, amount := range amountMap {
		m[address] = (amount > 0)
	}

	return m, nil

}

// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getbalance
func (c *Client) Balance(addr ...string) (map[string]uint64, error) {
	const dataTpl = `{"jsonrpc":"2.0","method":"eth_getBalance","params":["{{Address}}","latest"],"id":1}`
	type res struct {
		address string
		amount  uint64
		err     error
	}
	ch := make(chan res, len(addr))
	for _, address := range addr {
		go func(address string) {
			r := res{address: address}
			data := strings.Replace(dataTpl, "{{Address}}", address, 1)
			var b []byte
			b, r.err = c.makeReq(data)
			if r.err != nil {
				ch <- r
				return
			}
			var v Result
			if r.err = json.Unmarshal(b, &v); r.err != nil {
				r.err = fmt.Errorf("Err %v, B %s", r.err, b)
				ch <- r
				return
			}
			lit := strings.TrimPrefix(v.Result, "0x")
			r.amount, r.err = strconv.ParseUint(lit, 16, 64)
			ch <- r
		}(address)
	}
	m := make(map[string]uint64)
	for r := range ch {
		if r.err != nil {
			return nil, r.err
		}
		m[r.address] = r.amount
		if len(m) == len(addr) {
			break
		}
	}
	return m, nil
}

// This is only to implement wallet.Unspender.
// Todo: consider different interfaces based on coins.
func (c *Client) Unspent(cx context.Context, addr ...string) (map[string][]cryptopay.Unspent, error) {

	var amountMap map[string]uint64
	amountMap, err := c.Balance(addr...)
	if err != nil {
		return nil, err
	}
	m := make(map[string][]cryptopay.Unspent)
	for address, amount := range amountMap {
		m[address] = []cryptopay.Unspent{
			cryptopay.Unspent{Amount: amount, Confirmations: 9999}}
	}
	return m, nil
}

func (c *Client) makeReq(data string) ([]byte, error) {
	req, err := http.NewRequest("POST", c.endpoint, strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	rsp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(rsp.Body)
	rsp.Body.Close()
	return b, err
}
