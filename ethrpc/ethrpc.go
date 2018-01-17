package ethrpc

import (
	"context"
	"encoding/json"
	"fmt"
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
	const dataTpl = `{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["{{Address}}","latest"],"id":1}`
	for _, address := range addr {
		data := strings.Replace(dataTpl, "{{Address}}", address, 1)
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
		if err != nil {
			return nil, err
		}
		var v Result
		if err = json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("Err %v, B %s", err, b)
		}
		m[address], err = strconv.ParseUint(v.Result, 16, 0)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}
