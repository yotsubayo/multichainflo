package flo

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcutil"
	"github.com/renproject/multichain/api/address"
	"github.com/renproject/multichain/api/utxo"
	"github.com/renproject/pack"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"time"

	"github.com/bitspill/flod/chaincfg"
	"github.com/bitspill/flod/chaincfg/chainhash"
	"github.com/bitspill/flod/floec"
	"github.com/bitspill/flod/flojson"
	"github.com/bitspill/flod/txscript"
	"github.com/bitspill/flod/wire"
	"github.com/bitspill/floutil"
)

// Version of Bitcoin transactions supported by the multichain.
const Version int32 = 2

// The TxBuilder is an implementation of a UTXO-compatible transaction builder
// for Bitcoin.
type TxBuilder struct {
	params *chaincfg.Params
}

// NewTxBuilder returns a transaction builder that builds UTXO-compatible
// Bitcoin transactions for the given chain configuration (this means that it
// can be used for regnet, testnet, and mainnet, but also for networks that are
// minimally modified forks of the Bitcoin network).
func NewTxBuilder(params *chaincfg.Params) TxBuilder {
	return TxBuilder{params: params}
}

// BuildTx returns a Bitcoin transaction that consumes funds from the given
// inputs, and sends them to the given recipients. The difference in the sum
// value of the inputs and the sum value of the recipients is paid as a fee to
// the Bitcoin network. This fee must be calculated independently of this
// function. Outputs produced for recipients will use P2PKH, P2SH, P2WPKH, or
// P2WSH scripts as the pubkey script, based on the format of the recipient
// address.
func (txBuilder TxBuilder) BuildTx(inputs []utxo.Input, recipients []utxo.Recipient) (utxo.Tx, error) {
	msgTx := wire.NewMsgTx(Version)

	// Inputs
	for _, input := range inputs {
		hash := chainhash.Hash{}
		copy(hash[:], input.Hash)
		index := input.Index.Uint32()
		msgTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&hash, index), nil, nil))
	}

	// Outputs
	for _, recipient := range recipients {
		addr, err := floutil.DecodeAddress(string(recipient.To), txBuilder.params)
		if err != nil {
			return nil, err
		}
		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
		value := recipient.Value.Int().Int64()
		if value < 0 {
			return nil, fmt.Errorf("expected value >= 0, got value %v", value)
		}
		msgTx.AddTxOut(wire.NewTxOut(value, script))
	}

	return &Tx{inputs: inputs, recipients: recipients, msgTx: msgTx, signed: false}, nil
}

// Tx represents a simple Bitcoin transaction that implements the Bitcoin Compat
// API.
type Tx struct {
	inputs     []utxo.Input
	recipients []utxo.Recipient

	msgTx *wire.MsgTx

	signed bool
}

// Hash returns the transaction hash of the given underlying transaction.
func (tx *Tx) Hash() (pack.Bytes, error) {
	txhash := tx.msgTx.TxHash()
	return pack.NewBytes(txhash[:]), nil
}

// Inputs returns the UTXO inputs in the underlying transaction.
func (tx *Tx) Inputs() ([]utxo.Input, error) {
	return tx.inputs, nil
}

// Outputs returns the UTXO outputs in the underlying transaction.
func (tx *Tx) Outputs() ([]utxo.Output, error) {
	hash, err := tx.Hash()
	if err != nil {
		return nil, fmt.Errorf("bad hash: %v", err)
	}
	outputs := make([]utxo.Output, len(tx.msgTx.TxOut))
	for i := range outputs {
		outputs[i].Outpoint = utxo.Outpoint{
			Hash:  hash,
			Index: pack.NewU32(uint32(i)),
		}
		outputs[i].PubKeyScript = pack.Bytes(tx.msgTx.TxOut[i].PkScript)
		if tx.msgTx.TxOut[i].Value < 0 {
			return nil, fmt.Errorf("bad output %v: value is less than zero", i)
		}
		outputs[i].Value = pack.NewU256FromU64(pack.NewU64(uint64(tx.msgTx.TxOut[i].Value)))
	}
	return outputs, nil
}

// Sighashes returns the digests that must be signed before the transaction
// can be submitted by the client.
func (tx *Tx) Sighashes() ([]pack.Bytes32, error) {
	sighashes := make([]pack.Bytes32, len(tx.inputs))

	for i, txin := range tx.inputs {
		pubKeyScript := txin.PubKeyScript
		sigScript := txin.SigScript
		value := txin.Value.Int().Int64()
		if value < 0 {
			return []pack.Bytes32{}, fmt.Errorf("expected value >= 0, got value %v", value)
		}

		var hash []byte
		var err error
		if sigScript == nil {
			if txscript.IsPayToWitnessPubKeyHash(pubKeyScript) {
				hash, err = txscript.CalcWitnessSigHash(pubKeyScript, txscript.NewTxSigHashes(tx.msgTx), txscript.SigHashAll, tx.msgTx, i, value)
			} else {
				hash, err = txscript.CalcSignatureHash(pubKeyScript, txscript.SigHashAll, tx.msgTx, i)
			}
		} else {
			if txscript.IsPayToWitnessScriptHash(pubKeyScript) {
				hash, err = txscript.CalcWitnessSigHash(sigScript, txscript.NewTxSigHashes(tx.msgTx), txscript.SigHashAll, tx.msgTx, i, value)
			} else {
				hash, err = txscript.CalcSignatureHash(sigScript, txscript.SigHashAll, tx.msgTx, i)
			}
		}
		if err != nil {
			return []pack.Bytes32{}, err
		}

		sighash := [32]byte{}
		copy(sighash[:], hash)
		sighashes[i] = pack.NewBytes32(sighash)
	}

	return sighashes, nil
}

// Sign consumes a list of signatures, and adds them to the list of UTXOs in
// the underlying transactions.
func (tx *Tx) Sign(signatures []pack.Bytes65, pubKey pack.Bytes) error {
	if tx.signed {
		return fmt.Errorf("already signed")
	}
	if len(signatures) != len(tx.msgTx.TxIn) {
		return fmt.Errorf("expected %v signatures, got %v signatures", len(tx.msgTx.TxIn), len(signatures))
	}

	for i, rsv := range signatures {
		var err error

		// Decode the signature and the pubkey script.
		r := new(big.Int).SetBytes(rsv[:32])
		s := new(big.Int).SetBytes(rsv[32:64])
		signature := floec.Signature{
			R: r,
			S: s,
		}
		pubKeyScript := tx.inputs[i].Output.PubKeyScript
		sigScript := tx.inputs[i].SigScript

		// Support segwit.
		if sigScript == nil {
			if txscript.IsPayToWitnessPubKeyHash(pubKeyScript) || txscript.IsPayToWitnessScriptHash(pubKeyScript) {
				tx.msgTx.TxIn[i].Witness = wire.TxWitness([][]byte{append(signature.Serialize(), byte(txscript.SigHashAll)), pubKey})
				continue
			}
		} else {
			if txscript.IsPayToWitnessScriptHash(sigScript) || txscript.IsPayToWitnessScriptHash(sigScript) {
				tx.msgTx.TxIn[i].Witness = wire.TxWitness([][]byte{append(signature.Serialize(), byte(txscript.SigHashAll)), pubKey, sigScript})
				continue
			}
		}

		// Support non-segwit
		builder := txscript.NewScriptBuilder()
		builder.AddData(append(signature.Serialize(), byte(txscript.SigHashAll)))
		builder.AddData(pubKey)
		if sigScript != nil {
			builder.AddData(sigScript)
		}
		tx.msgTx.TxIn[i].SignatureScript, err = builder.Script()
		if err != nil {
			return err
		}
	}

	tx.signed = true
	return nil
}

// Serialize serializes the UTXO transaction to bytes
func (tx *Tx) Serialize() (pack.Bytes, error) {
	buf := new(bytes.Buffer)
	if err := tx.msgTx.Serialize(buf); err != nil {
		return pack.Bytes{}, err
	}
	return pack.NewBytes(buf.Bytes()), nil
}

// starting client
const (
	// DefaultClientTimeout used by the Client.
	DefaultClientTimeout = time.Minute
	// DefaultClientTimeoutRetry used by the Client.
	DefaultClientTimeoutRetry = time.Second
	// DefaultClientHost used by the Client. This should only be used for local
	// deployments of the multichain.
	DefaultClientHost = "http://0.0.0.0:8333"
	// DefaultClientUser used by the Client. This is insecure, and should only
	// be used for local — or publicly accessible — deployments of the
	// multichain.
	DefaultClientUser = "user"
	// DefaultClientPassword used by the Client. This is insecure, and should
	// only be used for local — or publicly accessible — deployments of the
	// multichain.
	DefaultClientPassword = "password"
)

// ClientOptions are used to parameterise the behaviour of the Client.
type ClientOptions struct {
	Timeout      time.Duration
	TimeoutRetry time.Duration
	Host         string
	User         string
	Password     string
}

// DefaultClientOptions returns ClientOptions with the default settings. These
// settings are valid for use with the default local deployment of the
// multichain. In production, the host, user, and password should be changed.
func DefaultClientOptions() ClientOptions {
	return ClientOptions{
		Timeout:      DefaultClientTimeout,
		TimeoutRetry: DefaultClientTimeoutRetry,
		Host:         DefaultClientHost,
		User:         DefaultClientUser,
		Password:     DefaultClientPassword,
	}
}

// WithHost sets the URL of the Bitcoin node.
func (opts ClientOptions) WithHost(host string) ClientOptions {
	opts.Host = host
	return opts
}

// WithUser sets the username that will be used to authenticate with the Bitcoin
// node.
func (opts ClientOptions) WithUser(user string) ClientOptions {
	opts.User = user
	return opts
}

// WithPassword sets the password that will be used to authenticate with the
// Bitcoin node.
func (opts ClientOptions) WithPassword(password string) ClientOptions {
	opts.Password = password
	return opts
}

// A Client interacts with an instance of the Bitcoin network using the RPC
// interface exposed by a Bitcoin node.
type Client interface {
	utxo.Client
	// UnspentOutputs spendable by the given address.
	UnspentOutputs(ctx context.Context, minConf, maxConf int64, address address.Address) ([]utxo.Output, error)
	// Confirmations of a transaction in the Bitcoin network.
	Confirmations(ctx context.Context, txHash pack.Bytes) (int64, error)
	// EstimateSmartFee
	EstimateSmartFee(ctx context.Context, numBlocks int64) (float64, error)
	// EstimateFeeLegacy
	EstimateFeeLegacy(ctx context.Context, numBlocks int64) (float64, error)
}

type client struct {
	opts       ClientOptions
	httpClient http.Client
}

// NewClient returns a new Client.
func NewClient(opts ClientOptions) Client {
	httpClient := http.Client{}
	httpClient.Timeout = opts.Timeout
	return &client{
		opts:       opts,
		httpClient: httpClient,
	}
}

// LatestBlock returns the height of the longest blockchain.
func (client *client) LatestBlock(ctx context.Context) (pack.U64, error) {
	var resp int64
	if err := client.send(ctx, &resp, "getblockcount"); err != nil {
		return pack.NewU64(0), fmt.Errorf("get block count: %v", err)
	}
	if resp < 0 {
		return pack.NewU64(0), fmt.Errorf("unexpected block count, expected > 0, got: %v", resp)
	}

	return pack.NewU64(uint64(resp)), nil
}

// Output associated with an outpoint, and its number of confirmations.
func (client *client) Output(ctx context.Context, outpoint utxo.Outpoint) (utxo.Output, pack.U64, error) {
	resp := flojson.TxRawResult{}
	hash := chainhash.Hash{}
	copy(hash[:], outpoint.Hash)
	if err := client.send(ctx, &resp, "getrawtransaction", hash.String(), 1); err != nil {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad \"getrawtransaction\": %v", err)
	}
	if outpoint.Index.Uint32() >= uint32(len(resp.Vout)) {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad index: %v is out of range", outpoint.Index)
	}
	vout := resp.Vout[outpoint.Index.Uint32()]
	amount, err := floutil.NewAmount(vout.Value)
	if err != nil {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad amount: %v", err)
	}
	if amount < 0 {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad amount: %v", amount)
	}
	pubKeyScript, err := hex.DecodeString(vout.ScriptPubKey.Hex)
	if err != nil {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad pubkey script: %v", err)
	}
	output := utxo.Output{
		Outpoint:     outpoint,
		Value:        pack.NewU256FromU64(pack.NewU64(uint64(amount))),
		PubKeyScript: pack.NewBytes(pubKeyScript),
	}
	return output, pack.NewU64(resp.Confirmations), nil
}

// UnspentOutput returns the unspent transaction output identified by the
// given outpoint. It also returns the number of confirmations for the
// output. If the output cannot be found before the context is done, the
// output is invalid, or the output has been spent, then an error should be
// returned.
func (client *client) UnspentOutput(ctx context.Context, outpoint utxo.Outpoint) (utxo.Output, pack.U64, error) {

	resp := flojson.GetTxOutResult{}
	hash := chainhash.Hash{}
	copy(hash[:], outpoint.Hash)
	if err := client.send(ctx, &resp, "gettxout", hash.String(), outpoint.Index.Uint32()); err != nil {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad \"gettxout\": %v", err)
	}
	amount, err := floutil.NewAmount(resp.Value)
	if err != nil {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad amount: %v", err)
	}
	if amount < 0 {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad amount: %v", amount)
	}
	if resp.Confirmations < 0 {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad confirmations: %v", resp.Confirmations)
	}
	pubKeyScript, err := hex.DecodeString(resp.ScriptPubKey.Hex)
	if err != nil {
		return utxo.Output{}, pack.NewU64(0), fmt.Errorf("bad pubkey script: %v", err)
	}
	output := utxo.Output{
		Outpoint:     outpoint,
		Value:        pack.NewU256FromU64(pack.NewU64(uint64(amount))),
		PubKeyScript: pack.NewBytes(pubKeyScript),
	}
	return output, pack.NewU64(uint64(resp.Confirmations)), nil
}

// SubmitTx to the Bitcoin network.
func (client *client) SubmitTx(ctx context.Context, tx utxo.Tx) error {
	serial, err := tx.Serialize()
	if err != nil {
		return fmt.Errorf("bad tx: %v", err)
	}
	resp := ""
	if err := client.send(ctx, &resp, "sendrawtransaction", hex.EncodeToString(serial)); err != nil {
		return fmt.Errorf("bad \"sendrawtransaction\": %v", err)
	}
	return nil
}

// UnspentOutputs spendable by the given address.
func (client *client) UnspentOutputs(ctx context.Context, minConf, maxConf int64, addr address.Address) ([]utxo.Output, error) {

	resp := []flojson.ListUnspentResult{}
	if err := client.send(ctx, &resp, "listunspent", minConf, maxConf, []string{string(addr)}); err != nil && err != io.EOF {
		return []utxo.Output{}, fmt.Errorf("bad \"listunspent\": %v", err)
	}
	outputs := make([]utxo.Output, len(resp))
	for i := range outputs {
		amount, err := btcutil.NewAmount(resp[i].Amount)
		if err != nil {
			return []utxo.Output{}, fmt.Errorf("bad amount: %v", err)
		}
		if amount < 0 {
			return []utxo.Output{}, fmt.Errorf("bad amount: %v", amount)
		}
		pubKeyScript, err := hex.DecodeString(resp[i].ScriptPubKey)
		if err != nil {
			return []utxo.Output{}, fmt.Errorf("bad pubkey script: %v", err)
		}
		txid, err := chainhash.NewHashFromStr(resp[i].TxID)
		if err != nil {
			return []utxo.Output{}, fmt.Errorf("bad txid: %v", err)
		}
		outputs[i] = utxo.Output{
			Outpoint: utxo.Outpoint{
				Hash:  pack.NewBytes(txid[:]),
				Index: pack.NewU32(resp[i].Vout),
			},
			Value:        pack.NewU256FromU64(pack.NewU64(uint64(amount))),
			PubKeyScript: pack.NewBytes(pubKeyScript),
		}
	}
	return outputs, nil
}

// Confirmations of a transaction in the Bitcoin network.
func (client *client) Confirmations(ctx context.Context, txHash pack.Bytes) (int64, error) {
	resp := flojson.GetTransactionResult{}

	size := len(txHash)
	txHashReversed := make([]byte, size)
	copy(txHashReversed[:], txHash[:])
	for i := 0; i < size/2; i++ {
		txHashReversed[i], txHashReversed[size-1-i] = txHashReversed[size-1-i], txHashReversed[i]
	}

	if err := client.send(ctx, &resp, "gettransaction", hex.EncodeToString(txHashReversed)); err != nil {
		return 0, fmt.Errorf("bad \"gettransaction\": %v", err)
	}
	confirmations := resp.Confirmations
	if confirmations < 0 {
		confirmations = 0
	}
	return confirmations, nil
}

// EstimateSmartFeeResult models the data returned buy the chain server
// estimatesmartfee command
type EstimateSmartFeeResult struct {
	FeeRate *float64 `json:"feerate,omitempty"`
	Errors  []string `json:"errors,omitempty"`
	Blocks  int64    `json:"blocks"`
}

// EstimateSmartFee fetches the estimated bitcoin network fees to be paid (in
// BTC per kilobyte) needed for a transaction to be confirmed within `numBlocks`
// blocks. An error will be returned if the bitcoin node hasn't observed enough
// blocks to make an estimate for the provided target `numBlocks`.
func (client *client) EstimateSmartFee(ctx context.Context, numBlocks int64) (float64, error) {
	resp := EstimateSmartFeeResult{}

	if err := client.send(ctx, &resp, "estimatesmartfee", numBlocks); err != nil {
		return 0.0, fmt.Errorf("estimating smart fee: %v", err)
	}

	if resp.Errors != nil && len(resp.Errors) > 0 {
		return 0.0, fmt.Errorf("estimating smart fee: %v", resp.Errors[0])
	}

	return *resp.FeeRate, nil
}

func (client *client) EstimateFeeLegacy(ctx context.Context, numBlocks int64) (float64, error) {
	var resp float64

	switch numBlocks {
	case int64(0):
		if err := client.send(ctx, &resp, "estimatefee"); err != nil {
			return 0.0, fmt.Errorf("estimating fee: %v", err)
		}
	default:
		if err := client.send(ctx, &resp, "estimatefee", numBlocks); err != nil {
			return 0.0, fmt.Errorf("estimating fee: %v", err)
		}
	}

	return resp, nil
}

func (client *client) send(ctx context.Context, resp interface{}, method string, params ...interface{}) error {
	// Encode the request.
	data, err := encodeRequest(method, params)
	if err != nil {
		return err
	}

	return retry(ctx, client.opts.TimeoutRetry, func() error {
		// Create request and add basic authentication headers. The context is
		// not attached to the request, and instead we all each attempt to run
		// for the timeout duration, and we keep attempting until success, or
		// the context is done.
		req, err := http.NewRequest("POST", client.opts.Host, bytes.NewBuffer(data))
		if err != nil {
			return fmt.Errorf("building http request: %v", err)
		}
		req.SetBasicAuth(client.opts.User, client.opts.Password)

		// Send the request and decode the response.
		res, err := client.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("sending http request: %v", err)
		}
		defer res.Body.Close()
		if err := decodeResponse(resp, res.Body); err != nil {
			return fmt.Errorf("decoding http response: %v", err)
		}
		return nil
	})
}

func encodeRequest(method string, params []interface{}) ([]byte, error) {
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("encoding params: %v", err)
	}
	req := struct {
		Version string          `json:"version"`
		ID      int             `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}{
		Version: "2.0",
		ID:      rand.Int(),
		Method:  method,
		Params:  rawParams,
	}
	rawReq, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}
	return rawReq, nil
}

func decodeResponse(resp interface{}, r io.Reader) error {
	res := struct {
		Version string           `json:"version"`
		ID      int              `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}{}
	if err := json.NewDecoder(r).Decode(&res); err != nil {
		return fmt.Errorf("decoding response: %v", err)
	}
	if res.Error != nil {
		return fmt.Errorf("decoding response: %v", string(*res.Error))
	}
	if res.Result == nil {
		return fmt.Errorf("decoding result: result is nil")
	}
	if err := json.Unmarshal(*res.Result, resp); err != nil {
		return fmt.Errorf("decoding result: %v", err)
	}
	return nil
}

func retry(ctx context.Context, dur time.Duration, f func() error) error {
	ticker := time.NewTicker(dur)
	err := f()
	for err != nil {
		log.Printf("retrying: %v", err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("%v: %v", ctx.Err(), err)
		case <-ticker.C:
			err = f()
		}
	}
	return nil
}
