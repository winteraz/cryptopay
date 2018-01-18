package ethrpc

import (
	"context"
	"encoding/json"
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
	m := make(map[string]uint64)
	var err error
	for _, address := range addr {
		m[address], err = c.CountTransactionsByAddress(cx, address)
		if err != nil {
			return nil, err
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
	cnt, err := strconv.ParseUint(v.Result, 16, 0)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (c *Client) HasTransactions(cx context.Context, addr ...string) (map[string]bool, error) {
	m := make(map[string]bool)
	for _, address := range addr {
		nonce, err := c.CountTransactionsByAddress(cx, address)
		if err != nil {
			return nil, err
		}
		var ok bool
		if nonce > 0 {
			ok = true
		} else {
			amount, err := c.Balance(address)
			if err != nil {
				return nil, err
			}
			if amount > 0 {
				ok = true
			}
		}
		m[address] = ok
	}
	return m, nil

}

// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getbalance
func (c *Client) Balance(address string) (uint64, error) {
	const dataTpl = `{"jsonrpc":"2.0","method":"eth_getBalance","params":["{{Address}}","latest"],"id":1}`
	data := strings.Replace(dataTpl, "{{Address}}", address, 1)
	b, err := c.makeReq(data)
	if err != nil {
		return 0, err
	}
	var v Result
	if err = json.Unmarshal(b, &v); err != nil {
		return 0, fmt.Errorf("Err %v, B %s", err, b)
	}
	return strconv.ParseUint(v.Result, 16, 0)
}

// This is only to implement wallet.Unspender.
// Todo: consider different interfaces based on coins.
func (c *Client) Unspent(cx context.Context, addr ...string) (map[string][]cryptopay.Unspent, error) {
	m := make(map[string][]cryptopay.Unspent)
	for _, address := range addr {
		amount, err := c.Balance(address)
		if err != nil {
			return nil, err
		}
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
