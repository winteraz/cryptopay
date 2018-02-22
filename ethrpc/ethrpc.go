package ethrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/golang/glog"
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
	Error   Error  `json:"error"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
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
	if address == "" {
		return 0, errors.New("invalid address")
	}
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
	r, err := strconv.ParseUint(lit, 16, 64)
	if err != nil {
		log.Errorf("lit %v, err %v", lit, err)
	}
	return r, err
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

type JSONRequest struct {
	Version string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
	ID      int      `json:"id"`
}

// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getbalance
func (c *Client) Balance(addr ...string) (map[string]uint64, error) {
	if len(addr) == 0 {
		return nil, errors.New("Invalid address list")
	}
	// http://www.jsonrpc.org/specification#batch
	// const dataTpl = `{"jsonrpc":"2.0","method":"eth_getBalance","params":["{{Address}}","latest"],"id":1}`
	var jra []JSONRequest
	for k, address := range addr {
		jr := JSONRequest{
			Version: "2.0",
			Method:  "eth_getBalance",
			Params:  []string{address, "latest"},
			ID:      k + 1,
		}
		jra = append(jra, jr)
	}
	b, err := json.Marshal(jra)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	b, err = c.makeReq(string(b))
	if err != nil {
		return nil, err
	}
	var ra []Result
	if err = json.Unmarshal(b, &ra); err != nil {
		log.Error(err)
		return nil, err
	}
	if len(ra) != len(addr) {
		err = fmt.Errorf("Received %v sent %v", len(ra), len(addr))
		log.Error(err)
		return nil, err
	}
	m := make(map[string]uint64)
	for _, v := range ra {
		if v.ID > len(addr) {
			err = fmt.Errorf("Unespected ID %v addr count %v", v.ID, len(addr))
			return nil, err
		}
		if v.Error.Code != 0 || v.Error.Message != "" {
			err = fmt.Errorf("%#v", v)
			log.Error(err)
			return nil, err
		}
		lit := strings.TrimPrefix(v.Result, "0x")
		m[addr[v.ID-1]], err = strconv.ParseUint(lit, 16, 64)
		if err != nil {
			log.Errorf("lit %s, err %v", lit, err)
			return nil, err
		}
	}
	return m, nil
}

// This is only to implement wallet.Unspender.
// Todo: consider different interfaces based on coins.
func (c *Client) Unspent(cx context.Context, addr ...string) (map[string][]cryptopay.Unspent, error) {
	if len(addr) == 0 {
		return nil, errors.New("Invalid address list")
	}
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

// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sendrawtransaction
func (c *Client) Broadcast(cx context.Context, txa ...string) (map[string]error, error) {
	if len(txa) == 0 {
		return nil, errors.New("Invalid address list")
	}
	var jra []JSONRequest
	for k, tx := range txa {
		jr := JSONRequest{
			Version: "2.0",
			Method:  "eth_sendRawTransaction",
			Params:  []string{tx},
			ID:      k + 1,
		}
		jra = append(jra, jr)
	}
	b, err := json.Marshal(jra)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	b, err = c.makeReq(string(b))
	if err != nil {
		return nil, err
	}
	var ra []Result
	if err = json.Unmarshal(b, &ra); err != nil {
		log.Error(err)
		return nil, err
	}
	if len(ra) != len(txa) {
		err = fmt.Errorf("Received %v sent %v", len(ra), len(txa))
		log.Error(err)
		return nil, err
	}
	m := make(map[string]error)
	for _, v := range ra {
		if v.ID > len(txa) {
			err = fmt.Errorf("Unespected ID %v addr count %v", v.ID, len(txa))
			return nil, err
		}
		if v.Error.Code != 0 || v.Error.Message != "" {
			err = fmt.Errorf("%#v", v)
			m[txa[v.ID-1]] = err
			continue
		}

		lit := strings.TrimPrefix(v.Result, "0x")
		_, err := strconv.ParseUint(lit, 16, 64)
		m[txa[v.ID-1]] = err
		if err != nil {
			log.Errorf("lit %s, err %v", lit, err)
		}
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
