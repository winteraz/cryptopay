package cryptopay

import (
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"

	"github.com/alfg/blockchain"

	log "github.com/golang/glog"
)

var ErrZeroBalance = errors.New("Balance is zero")

//  https://bitcoin.stackexchange.com/a/7857/69359
//  To send bitcoins you need:
//  Private key(s) for the address(es) being spent
//  Transaction hash + index for each transaction previously received to those addresses
//  whose funds will be used for spending in this transaction
//  Bitcoin address(es) to send to
// receives from private key(base58) of the address where the funds are
// and the bitcoin address where the funds will be sent
// It uses blockchain.info API to get the public address history so that it can create a transaction.
func Transfer(from, to string) (*wire.MsgTx, int64, error) {
	privKey, err := hdkeychain.NewKeyFromString(from)
	if err != nil {
		log.Error(err)
		return nil, 0, err
	}
	ecPriv, err := privKey.ECPrivKey()
	if err != nil {
		log.Error(err)
		return nil, 0, err
	}
	originTx, unspentBalance, err := Unspent(from)
	if err != nil {
		log.Error(err)
		return nil, 0, err
	}
	if unspentBalance == 0 {
		return nil, 0, ErrZeroBalance
	}
	version := int32(0) // where we get this ?
	// Create the transaction to redeem the unspent coins.
	redeemTx := wire.NewMsgTx(version)
	// Add the input(s) the redeeming transaction will spend.  There is no
	// signature script at this point since it hasn't been created or signed
	// yet, hence nil is provided for it.
	var index uint32 = 0
	prevOut := wire.NewOutPoint(nil, index)
	var signatureScript []byte // ?? How to generate this???
	var witness [][]byte       // How to generate this ???
	txIn := wire.NewTxIn(prevOut, signatureScript, witness)
	redeemTx.AddTxIn(txIn)

	// Destination of the funds
	txOut, err := NewOutTransaction(to, unspentBalance)
	redeemTx.AddTxOut(txOut)

	// Sign the redeeming transaction.
	pkScript := originTx.TxOut[0].PkScript

	sigScript, err := txscript.SignatureScript(redeemTx, 0, pkScript, txscript.SigHashAll, ecPriv, true)
	if err != nil {
		log.Error(err)
		return nil, 0, err
	}
	redeemTx.TxIn[0].SignatureScript = sigScript //?
	// Prove that the transaction has been validly signed by executing the scripts.
	flags := txscript.StandardVerifyFlags
	var (
		sigCache    *txscript.SigCache    // where to get this?
		hashCache   *txscript.TxSigHashes // where to get this?
		inputAmount int64                 // where to get this?
	)
	vm, err := txscript.NewEngine(pkScript, redeemTx, 0, flags, sigCache, hashCache, inputAmount)
	if err != nil {
		log.Error(err)
		return nil, 0, err
	}
	if err := vm.Execute(); err != nil {
		log.Error(err)
		return nil, 0, err
	}
	return redeemTx, unspentBalance, nil
}

// receives a bitcoin address and returns a new out transaction
func NewOutTransaction(to string, amount int64) (*wire.TxOut, error) {
	addr, err := btcutil.DecodeAddress(to, &chaincfg.MainNetParams)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(amount, pkScript), nil
}

// Receives the public bitcoin public address.
// Returns the previous transactions as a wire message
// and the total amount available to transfer.
// We are using blockchain.info to get the transactionhash
// + index for each transaction previously received.
func Unspent(address string) (*wire.MsgTx, int64, error) {
	var err error
	cl, err := blockchain.New()
	if err != nil {
		log.Error(err)
		return nil, 0, err
	}
	var addr *blockchain.Address
	addr, err = cl.GetAddress(address)
	if err != nil {
		log.Error(err)
		return nil, 0, err
	}
	var version int32 = 0 // where to get this ????
	tx := wire.NewMsgTx(version)
	for _, bktx := range addr.Txs {
		for _, out := range bktx.Out {
			script, err := hex.DecodeString(out.Script)
			if err != nil {
				return nil, 0, err
			}
			txout := wire.NewTxOut(int64(out.Value), script)
			tx.AddTxOut(txout)
		}
		for _, in := range bktx.Inputs {
			txIn, err := chainInputToTx(in)
			if err != nil {
				log.Error(err)
				return nil, 0, err
			}
			tx.AddTxIn(txIn)
		}
	}
	return tx, int64(addr.FinalBalance), nil
}

func chainInputToTx(tx *blockchain.Inputs) (*wire.TxIn, error) {
	script, err := hex.DecodeString(tx.Script)
	if err != nil {
		return nil, err
	}
	// WHERE to get this ??? Inputs doesn't have transaction hash
	// only the transaction(parent) itself hash a hash.
	// currently we use dummy/empty value
	var inputHash string
	hash := chainhash.Hash{}
	if err := chainhash.Decode(&hash, inputHash); err != nil {
		return nil, err
	}
	var witness [][]byte // how to decode this??? this is provided as a string by blockchain API
	outPoint := wire.NewOutPoint(&hash, uint32(tx.PrevOut.TxIndex))
	txIn := wire.NewTxIn(outPoint, script, witness)
	return txIn, nil
}
