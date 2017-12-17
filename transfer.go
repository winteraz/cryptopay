package cryptopay

import (
	"encoding/hex"
	"errors"
	"flag"

	"github.com/bartekn/go-bip39"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip32"

	"github.com/alfg/blockchain"

	log "github.com/golang/glog"
)

func main() {
	flag.Parse()
	defer log.Flush()
	// Generate a seed to determine all keys from.
	// This should be persisted, backed up, and secured
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Error(err)
		return
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Error(err)
		return
	}
	// our mnemonic
	mnemonic = "tape sword sausage potato scare false grow small barrel river auto goat enlist range inhale impose select blast assist clog hint easy spoon title"
	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed := bip39.NewSeed(mnemonic, "somepassword")
	// Create master private key from seed
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Error(err)
		return
	}
	log.Errorf("mnemonic %s\n master %s", mnemonic, masterKey.B58Serialize())
	var children = map[string]string{}
	//	defaultNet := &chaincfg.MainNetParams
	var addra []string
	for i := uint32(0); i <= 10; i++ {
		k, err := masterKey.NewChildKey(i)
		if err != nil {
			log.Error(err)
			continue
		}
		children[k.B58Serialize()] = k.PublicKey().B58Serialize()
		//	pubByte, err := k.PublicKey().Serialize()

		//	addra = append(addra, addr.EncodeAddress())
		addr, err := BTCAddr(k.PublicKey().B58Serialize())
		if err != nil {
			log.Error(err)
			return
		}
		addra = append(addra, addr)
	}
	log.Errorf("address is %q", addra)
	return
}



var ErrZeroBalance = errors.New("Balance is zero")

//  https://bitcoin.stackexchange.com/a/7857/69359
//  To send bitcoins you need:
//  Private key(s) for the address(es) being spent
//  Transaction hash + index for each transaction previously received to those addresses whose funds will be used for spending in this transaction
//  Bitcoin address(es) to send to, including change address if there will be change.
// receives from private key of the address
func Transfer(from, to string) (*wire.MsgTx, int64, error) {
	privKey, err := hdkeychain.NewKeyFromString(from)
	if err != nil {
		log.Error(err)
		return nil, 0, err
	}
	ecPriv, err := privKey.ECPrivKey()
	if err != nil{
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
	var witness [][]byte // How to generate this ???
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
		sigCache *txscript.SigCache // where to get this?
		hashCache *txscript.TxSigHashes // where to get this?
		inputAmount int64 // where to get this?
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
func NewOutTransaction(to string, amount int64)(*wire.TxOut, error){
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
			prevIn, script, err := chainInToOutpoint(in)
			if err != nil {
				log.Error(err)
				return nil, 0, err
			}
			var  witness [][]byte // where to get this?
			txIn := wire.NewTxIn(prevIn, script, witness)
			tx.AddTxIn(txIn)
		}
	}
	return tx, int64(addr.FinalBalance), nil
}


func chainInToOutpoint(tx *blockchain.Inputs) (*wire.OutPoint, []byte, error) {
	hash := chainhash.Hash{}
	// WHERE to get this ??? Inputs doesn't have transaction hash 
	// only the transaction(parent) itself hash a hash.
	var inputHash string 
	if err := chainhash.Decode(&hash, inputHash); err != nil {
		return nil, nil, err
	}
	script, err := hex.DecodeString(tx.Script)
	if err != nil {
		return nil, nil, err
	}
	return wire.NewOutPoint(&hash, uint32(tx.PrevOut.TxIndex)), script, nil
}
