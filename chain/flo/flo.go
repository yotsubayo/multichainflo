package flo

import (
	"github.com/bitspill/flod/chaincfg"
	"github.com/bitspill/flod/chaincfg/chainhash"
	"github.com/bitspill/flod/wire"
	"math"
	"math/big"
	"time"
)

func init() {
	if err := chaincfg.Register(&MainNetParams); err != nil {
		panic(err)
	}
	if err := chaincfg.Register(&TestNetParams); err != nil {
		panic(err)
	}
	if err := chaincfg.Register(&RegressionNetParams); err != nil {
		panic(err)
	}
}

// newHashFromStr converts the passed big-endian hex string into a
// wire.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		panic(err)
	}
	return hash
}

var (

	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a Bitcoin block can
	// have for the main network.  It is the value 2^224 - 1.
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 236), bigOne)

	// testNetPowLimit is the highest proof of work value a Bitcoin block
	// can have for the test network (version 3).  It is the value
	// 2^236 - 1.
	testNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 236), bigOne)

	// regressionPowLimit is the highest proof of work value a Bitcoin block
	// can have for the regression test network.  It is the value 2^255 - 1.
	regressionPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
)

// Constants that define the deployment offset in the deployments field of the
// parameters for each deployment.  This is useful to be able to get the details
// of a specific deployment by name.
const (
	// DeploymentTestDummy defines the rule change deployment ID for testing
	// purposes.
	DeploymentTestDummy = iota

	// DeploymentCSV defines the rule change deployment ID for the CSV
	// soft-fork package. The CSV package includes the deployment of BIPS
	// 68, 112, and 113.
	DeploymentCSV

	// DeploymentSegwit defines the rule change deployment ID for the
	// Segregated Witness (segwit) soft-fork package. The segwit package
	// includes the deployment of BIPS 141, 142, 144, 145, 147 and 173.
	DeploymentSegwit

	// NOTE: DefinedDeployments must always come last since it is used to
	// determine how many defined deployments there currently are.

	// DefinedDeployments is the number of currently defined deployments.
	DefinedDeployments
)

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network, regression test network, and test network (version 3).
var genesisCoinbaseTx = wire.MsgTx{
	Version: 2,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			SignatureScript: []byte{
				0x53, 0x6c, 0x61, 0x73, 0x68, 0x64, 0x6f, 0x74, /* | Slashdot | */
				0x20, 0x2d, 0x20, 0x31, 0x37, 0x20, 0x4a, 0x75, /* |  - 17 Ju | */
				0x6e, 0x65, 0x20, 0x32, 0x30, 0x31, 0x33, 0x20, /* | ne 2013  | */
				0x2d, 0x20, 0x53, 0x61, 0x75, 0x64, 0x69, 0x20, /* | - Saudi  | */
				0x41, 0x72, 0x61, 0x62, 0x69, 0x61, 0x20, 0x53, /* | Arabia S | */
				0x65, 0x74, 0x20, 0x54, 0x6f, 0x20, 0x42, 0x61, /* | et To Ba | */
				0x6e, 0x20, 0x57, 0x68, 0x61, 0x74, 0x73, 0x41, /* | n WhatsA | */
				0x70, 0x70, 0x2c, 0x20, 0x53, 0x6b, 0x79, 0x70, /* | pp, Skyp | */
				0x65, /* | e | */
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value: 0x12a05f200,
			PkScript: []byte{
				0x41, 0x04, 0x01, 0x84, 0x71, 0x0f, 0xa6, 0x89,
				0xad, 0x50, 0x23, 0x69, 0x0c, 0x80, 0xf3, 0xa4,
				0x9c, 0x8f, 0x13, 0xf8, 0xd4, 0x5b, 0x8c, 0x85,
				0x7f, 0xbc, 0xbc, 0x8b, 0xc4, 0xa8, 0xe4, 0xd3,
				0xeb, 0x4b, 0x10, 0xf4, 0xd4, 0x60, 0x4f, 0xa0,
				0x8d, 0xce, 0x60, 0x1a, 0xaf, 0x0f, 0x47, 0x02,
				0x16, 0xfe, 0x1b, 0x51, 0x85, 0x0b, 0x4a, 0xcf,
				0x21, 0xb1, 0x79, 0xc4, 0x50, 0x70, 0xac, 0x7b,
				0x03, 0xa9, 0xac,
			},
		},
	},
	FloData:  []byte("text:Florincoin genesis block"),
	LockTime: 0,
}

// genesisHash is the hash of the first block in the block chain for the main
// network (genesis block).
var genesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0xea, 0x1c, 0x3e, 0xff, 0x7c, 0x4b, 0x27, 0x67,
	0xba, 0x56, 0x1c, 0xdd, 0xfc, 0xec, 0xd7, 0x41,
	0x90, 0x5c, 0xea, 0x38, 0x5d, 0xc3, 0x78, 0xe2,
	0x08, 0x07, 0xf9, 0x9d, 0x1c, 0x78, 0xc7, 0x09,
})

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network.
var genesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x00, 0x23, 0x2b, 0xab, 0xa7, 0x29, 0x1c, 0x9d,
	0x84, 0x4b, 0xb2, 0x48, 0x67, 0xaa, 0xfe, 0x45,
	0x3e, 0xa7, 0xe2, 0x90, 0x68, 0x56, 0x12, 0x55,
	0x2d, 0x59, 0x5a, 0xdc, 0x8d, 0x0c, 0x0f, 0x73,
})

// genesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var genesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: genesisMerkleRoot,        // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(0x51bf408c, 0), // 2009-01-03 18:15:05 +0000 UTC
		Bits:       0x1e0ffff0,               // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0x3b9c81a4,               // 2083236893
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// testNetGenesisHash is the hash of the first block in the block chain for the
// test network (version 3).
var testNetGenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x31, 0x37, 0xe0, 0x27, 0x8a, 0x19, 0x2a, 0xda,
	0xf0, 0xa1, 0xa7, 0x22, 0x6c, 0x96, 0x7a, 0x80,
	0xe8, 0x7f, 0x6b, 0x03, 0x7c, 0x36, 0x39, 0x3a,
	0x5e, 0x4b, 0xc3, 0x36, 0x62, 0xc8, 0x7b, 0x9b,
})

// testNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 3).  It is the same as the merkle root
// for the main network.
var testNetGenesisMerkleRoot = genesisMerkleRoot

// testNetGenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var testNetGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: testNetGenesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(1371387277, 0), // 2011-02-02 23:16:42 +0000 UTC
		Bits:       0x1e0ffff0,               // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      1000580675,               // 414098458
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// regTestGenesisHash is the hash of the first block in the block chain for the
// regression test network (genesis block).
var regTestGenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0xd7, 0xe0, 0xde, 0xa8, 0xb9, 0xd5, 0x17, 0x89,
	0xdb, 0x36, 0x57, 0x8d, 0x6f, 0x56, 0xa4, 0x5e,
	0x93, 0x61, 0xb1, 0x24, 0x1d, 0x9a, 0xb5, 0x03,
	0x11, 0xcb, 0x6d, 0xca, 0x26, 0xfa, 0x42, 0xec,
})

// regTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var regTestGenesisMerkleRoot = genesisMerkleRoot

// regTestGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the regression test network.
var regTestGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: regTestGenesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(1371387277, 0), // 2011-02-02 23:16:42 +0000 UTC
		Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      0,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// MainNetParams returns the chain configuration for mainnet.
var MainNetParams = chaincfg.Params{
	Name:        "mainnet",
	Net:         0xd9b4bef9,
	DefaultPort: "8333",
	DNSSeeds: []chaincfg.DNSSeed{
		{"flodns.oip.fun", false},
		{"flodns.oip.li", false},
		{"node.oip.fun", false},
	},

	// Chain parameters
	GenesisBlock:                 &genesisBlock,
	GenesisHash:                  &genesisHash,
	PowLimit:                     mainPowLimit,
	PowLimitBits:                 0x1d00ffff,
	BIP0034Height:                227931, // 000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8
	BIP0065Height:                388381, // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
	BIP0066Height:                363725, // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
	CoinbaseMaturity:             100,
	SubsidyReductionInterval:     210000,
	TargetTimespan:               time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:           time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactorUp:   4,                   // 25% less, 400% more
	RetargetAdjustmentFactorDown: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:          false,
	MinDiffReductionTime:         0,
	GenerateSupported:            false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []chaincfg.Checkpoint{
		{11111, newHashFromStr("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
		{33333, newHashFromStr("000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
		{74000, newHashFromStr("0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
		{105000, newHashFromStr("00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
		{134444, newHashFromStr("00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
		{168000, newHashFromStr("000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
		{193000, newHashFromStr("000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
		{210000, newHashFromStr("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
		{216116, newHashFromStr("00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")},
		{225430, newHashFromStr("00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")},
		{250000, newHashFromStr("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
		{267300, newHashFromStr("000000000000000a83fbd660e918f218bf37edd92b748ad940483c7c116179ac")},
		{279000, newHashFromStr("0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")},
		{300255, newHashFromStr("0000000000000000162804527c6e9b9f0563a280525f9d08c12041def0a0f3b2")},
		{319400, newHashFromStr("000000000000000021c6052e9becade189495d1c539aa37c58917305fd15f13b")},
		{343185, newHashFromStr("0000000000000000072b8bf361d01a6ba7d445dd024203fafc78768ed4368554")},
		{352940, newHashFromStr("000000000000000010755df42dba556bb72be6a32f3ce0b6941ce4430152c9ff")},
		{382320, newHashFromStr("00000000000000000a8dc6ed5b133d0eb2fd6af56203e4159789b092defd8ab2")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1916, // 95% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016, //
	Deployments: [DefinedDeployments]chaincfg.ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  1199145601, // January 1, 2008 UTC
			ExpireTime: 1230767999, // December 31, 2008 UTC
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  1462060800, // May 1st, 2016
			ExpireTime: 1493596800, // May 1st, 2017
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  1479168000, // November 15, 2016 UTC
			ExpireTime: 1510704000, // November 15, 2017 UTC.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: false,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "bc", // always bc for main net

	// Address encoding magics
	PubKeyHashAddrID:        0x00, // starts with 1
	ScriptHashAddrID:        0x05, // starts with 3
	PrivateKeyID:            0x80, // starts with 5 (uncompressed) or K (compressed)
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,
}

// TestNetParams returns the chain configuration for testnet.
var TestNetParams = chaincfg.Params{
	Name:        "testnet",
	Net:         0xf25ac0fd,
	DefaultPort: "8333",
	DNSSeeds: []chaincfg.DNSSeed{
		{"testnet.oip.fun", false},
	},

	// Chain parameters
	GenesisBlock:                 &testNetGenesisBlock,
	GenesisHash:                  &testNetGenesisHash,
	PowLimit:                     testNetPowLimit,
	PowLimitBits:                 0x1e0fffff,
	BIP0034Height:                33600, // 4ac31d938531317c065405a9b23478c8c99204ff17fc294cb09821e2c2b42e65
	BIP0065Height:                33600, // 4ac31d938531317c065405a9b23478c8c99204ff17fc294cb09821e2c2b42e65
	BIP0066Height:                33600, // 4ac31d938531317c065405a9b23478c8c99204ff17fc294cb09821e2c2b42e65
	CoinbaseMaturity:             100,
	SubsidyReductionInterval:     800000,
	TargetTimespan:               time.Second * 40 * 6, // 40 seconds * 6 blocks
	TargetTimePerBlock:           time.Second * 40,     // 40 seconds
	RetargetAdjustmentFactorUp:   2,
	RetargetAdjustmentFactorDown: 3,
	ReduceMinDifficulty:          true,
	MinDiffReductionTime:         time.Second * 80, // TargetTimePerBlock * 2
	GenerateSupported:            false,
	PowNoRetargeting:             false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []chaincfg.Checkpoint{
		{2056, newHashFromStr("d3334db071731beaa651f10624c2fea1a5e8c6f9e50f0e602f86262938374148")},
		{230000, newHashFromStr("c2e6451240a580c3bfa5ddbfad1b001f8655e7c51d5c32c123e16f69c2d2b539")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 600, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       800,
	Deployments: [DefinedDeployments]chaincfg.ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  1199145601, // January 1, 2008 UTC
			ExpireTime: 1230767999, // December 31, 2008 UTC
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  1483228800, // January 1, 2017
			ExpireTime: 1530446401, // July 1, 2018
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  1483228800, // January 1, 2017
			ExpireTime: 1530446401, // July 1, 2018
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "tb", // always tb for test net

	// Address encoding magics
	PubKeyHashAddrID: 115, // starts with m or n
	ScriptHashAddrID: 198, // starts with 2
	// 58
	WitnessPubKeyHashAddrID: 0x03, // starts with QW
	WitnessScriptHashAddrID: 0x28, // starts with T7n
	PrivateKeyID:            239,  // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x01, 0x34, 0x40, 0xe2}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x01, 0x34, 0x3c, 0x23}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}

// RegressionNetParams returns the chain configuration for regression net.
var RegressionNetParams = chaincfg.Params{
	Name:        "regtest",
	Net:         0xdab5bffa,
	DefaultPort: "8333",
	DNSSeeds:    []chaincfg.DNSSeed{},

	// Chain parameters
	GenesisBlock:                 &regTestGenesisBlock,
	GenesisHash:                  &regTestGenesisHash,
	PowLimit:                     regressionPowLimit,
	PowLimitBits:                 0x207fffff,
	CoinbaseMaturity:             100,
	BIP0034Height:                100000000, // Not active - Permit ver 1 blocks
	BIP0065Height:                1351,      // Used by regression tests
	BIP0066Height:                1251,      // Used by regression tests
	SubsidyReductionInterval:     150,
	TargetTimespan:               time.Second * 40 * 6, // 40 seconds * 6 blocks
	TargetTimePerBlock:           time.Second * 40,     // 40 seconds
	RetargetAdjustmentFactorUp:   2,                    // 25% less, 400% more
	RetargetAdjustmentFactorDown: 3,
	ReduceMinDifficulty:          true,
	MinDiffReductionTime:         time.Second * 80, // TargetTimePerBlock * 2
	GenerateSupported:            true,
	PowNoRetargeting:             true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 108, // 75%  of MinerConfirmationWindow
	MinerConfirmationWindow:       144, // Faster than normal for regtest (144 instead of 2016)
	Deployments: [DefinedDeployments]chaincfg.ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "rflo", // always rflo for reg test net

	// Address encoding magics
	PubKeyHashAddrID: 115,
	ScriptHashAddrID: 198,
	PrivateKeyID:     239, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}
