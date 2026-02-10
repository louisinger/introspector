package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	introspectorclient "github.com/ArkLabsHQ/introspector/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	inmemorystoreconfig "github.com/arkade-os/go-sdk/store/inmemory"
	singlekeywallet "github.com/arkade-os/go-sdk/wallet/singlekey"
	inmemorystore "github.com/arkade-os/go-sdk/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestSettlementWithAsset tests the settlement flow with an asset packet in the intent.
// Similar to TestSettlement but includes asset introspection in the arkade script.
func TestSettlementWithAsset(t *testing.T) {
	ctx := context.Background()
	alice, grpcClient := setupArkSDK(t)
	defer grpcClient.Close()

	bobPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	configStore, err := inmemorystoreconfig.NewConfigStore()
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)

	bobWallet, err := singlekeywallet.NewBitcoinWallet(
		configStore,
		walletStore,
	)
	require.NoError(t, err)

	_, err = bobWallet.Create(ctx, password, hex.EncodeToString(bobPrivKey.Serialize()))
	require.NoError(t, err)

	_, err = bobWallet.Unlock(ctx, password)
	require.NoError(t, err)

	bobPubKey := bobPrivKey.PubKey()

	// Fund Alice's account
	_, offchainAddr, boardingAddress, err := alice.Receive(ctx)
	require.NoError(t, err)

	aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = alice.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	const sendAmount = 10000
	const assetAmount = 500

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	// Script that verifies:
	// 1. Output goes to alice's address
	// 2. Asset packet has 1 group
	// 3. Asset is an issuance
	// 4. Asset output sum equals assetAmount
	arkadeScript, err := txscript.NewScriptBuilder().
		// Check output 0 goes to alice's address
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(alicePkScript[2:]). // only witness program
		AddOp(arkade.OP_EQUALVERIFY).
		// Check: 1 asset group
		AddOp(arkade.OP_INSPECTNUMASSETGROUPS).
		AddInt64(1).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check: group 0 is an issuance (AssetId.txid == this txid)
		AddInt64(0).
		AddOp(arkade.OP_INSPECTASSETGROUPASSETID).
		AddOp(arkade.OP_DROP). // drop gidx
		AddOp(arkade.OP_TXID).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check: sum of outputs for group 0 equals assetAmount
		AddInt64(0). // group index
		AddInt64(1). // source = outputs
		AddOp(arkade.OP_INSPECTASSETGROUPSUM).
		AddInt64(assetAmount).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	// create the client
	conn, err := grpc.NewClient("localhost:7073", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	introspectorClient := introspectorclient.NewGRPCClient(conn)

	introspectorInfo, err := introspectorClient.GetInfo(ctx)
	require.NoError(t, err)
	require.NotNil(t, introspectorInfo)

	publicKeyBytes, err := hex.DecodeString(introspectorInfo.SignerPublicKey)
	require.NoError(t, err)
	publicKey, err := btcec.ParsePubKey(publicKeyBytes)
	require.NoError(t, err)

	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					bobPubKey,
					aliceAddr.Signer,
					arkade.ComputeArkadeScriptPublicKey(
						publicKey,
						arkade.ArkadeScriptHash(arkadeScript),
					),
				},
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{
						bobPubKey,
						aliceAddr.Signer,
					},
				},
				Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512 * 10},
			},
		},
	}

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	contractAddress := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     aliceAddr.Signer,
	}

	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(arkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	contractAddressStr, err := contractAddress.EncodeV0()
	require.NoError(t, err)

	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: contractAddressStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	indexerSvc := setupIndexer(t)

	fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTx)
	require.Len(t, fundingTx.Txs, 1)

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
	require.NoError(t, err)

	var contractOutput *wire.TxOut
	var contractOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(contractAddress.VtxoTapKey)) {
			contractOutput = out
			contractOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, contractOutput)

	// Create the intent with asset packet

	randomKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	treeSignerSession := tree.NewTreeSignerSession(randomKey)
	require.NoError(t, err)

	message, err := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		OnchainOutputIndexes: nil,
		ExpireAt:             0,
		ValidAt:              0,
		CosignersPublicKeys:  []string{treeSignerSession.GetPublicKey()},
	}.Encode()
	require.NoError(t, err)

	intentProof, err := intent.New(
		message,
		[]intent.Input{
			{
				OutPoint: &wire.OutPoint{
					Hash:  redeemPtx.UnsignedTx.TxHash(),
					Index: contractOutputIndex,
				},
				Sequence:    wire.MaxTxInSequenceNum,
				WitnessUtxo: contractOutput,
			},
		},
		[]*wire.TxOut{
			{
				Value:    contractOutput.Value,
				PkScript: alicePkScript,
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, intentProof)

	// Add asset packet to intent transaction
	assetGroup, err := asset.NewAssetGroup(
		nil, // nil AssetId means issuance
		nil, // no control asset
		[]asset.AssetInput{}, // no inputs (issuance)
		[]asset.AssetOutput{
			{
				Vout:   0, // asset goes to output 0
				Amount: assetAmount,
			},
		},
		[]asset.Metadata{}, // no metadata
	)
	require.NoError(t, err)

	assetPacket, err := asset.NewPacket([]asset.AssetGroup{*assetGroup})
	require.NoError(t, err)

	assetPacketOut, err := assetPacket.TxOut()
	require.NoError(t, err)

	// Add asset packet as OP_RETURN output to intent transaction
	intentProof.UnsignedTx.AddTxOut(assetPacketOut)
	intentProof.Outputs = append(intentProof.Outputs, psbt.POutput{})

	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)
	taptreeField, err := txutils.VtxoTaprootTreeField.Encode(tapscripts)
	require.NoError(t, err)

	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	tapLeafScript := []*psbt.TaprootTapLeafScript{
		{
			LeafVersion:  txscript.BaseLeafVersion,
			ControlBlock: ctrlBlockBytes,
			Script:       merkleProof.Script,
		},
	}
	intentProof.Inputs[0].TaprootLeafScript = tapLeafScript
	intentProof.Inputs[1].TaprootLeafScript = tapLeafScript
	intentProof.Inputs[0].Unknowns = append(intentProof.Inputs[0].Unknowns, taptreeField)
	intentProof.Inputs[1].Unknowns = append(intentProof.Inputs[1].Unknowns, taptreeField)

	intentPtx := &intentProof.Packet
	err = txutils.SetArkPsbtField(intentPtx, 1, arkade.ArkadeScriptField, arkadeScript)
	require.NoError(t, err)

	encodedIntentProof, err := intentPtx.B64Encode()
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	signedIntentProof, err := bobWallet.SignTransaction(ctx, explorer, encodedIntentProof)
	require.NoError(t, err)
	require.NotEqual(t, signedIntentProof, encodedIntentProof)

	// SubmitIntent will execute the arkade script on the intent tx with the asset packet
	approvedIntentProof, err := introspectorClient.SubmitIntent(ctx, introspectorclient.Intent{
		Proof:   signedIntentProof,
		Message: message,
	})
	require.NoError(t, err)

	signedIntent := introspectorclient.Intent{
		Proof:   approvedIntentProof,
		Message: message,
	}

	intentId, err := grpcClient.RegisterIntent(ctx, signedIntent.Proof, signedIntent.Message)
	require.NoError(t, err)

	vtxo := client.TapscriptsVtxo{
		Vtxo: types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: redeemPtx.UnsignedTx.TxHash().String(),
				VOut: contractOutputIndex,
			},
			Script: hex.EncodeToString(arkadeTapscript),
			Amount: uint64(contractOutput.Value),
		},
		Tapscripts: tapscripts,
	}

	introspectorBatchHandler := &delegateBatchEventsHandler{
		intentId:           intentId,
		intent:             signedIntent,
		vtxosToForfeit:     []client.TapscriptsVtxo{vtxo},
		signerSession:      treeSignerSession,
		introspectorClient: introspectorClient,
		wallet:             bobWallet,
		client:             grpcClient,
	}

	topics := arksdk.GetEventStreamTopics([]types.Outpoint{vtxo.Outpoint}, []tree.SignerSession{treeSignerSession})
	eventStream, stop, err := grpcClient.GetEventStream(ctx, topics)
	require.NoError(t, err)
	t.Cleanup(func() {
		stop()
	})

	commitmentTxid, err := arksdk.JoinBatchSession(ctx, eventStream, introspectorBatchHandler)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
}
