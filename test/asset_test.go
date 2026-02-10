package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestOffchainTxWithAsset tests an offchain transaction with asset introspection opcodes.
// The test creates a simple asset packet with one asset group (issuance) and verifies
// that the arkade script can correctly inspect the asset using the introspection opcodes.
func TestOffchainTxWithAsset(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer grpcAlice.Close()

	bobWallet, _, bobPubKey := setupBobWallet(t, ctx)
	aliceAddr := fundAndSettleAlice(t, ctx, alice)

	const sendAmount = 10000
	const assetAmount = 1000

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	assetPacket := createAssetPacket(t, 0, assetAmount)
	arkadeScript := createArkadeScriptWithAssetChecks(t, alicePkScript, assetAmount)
	introspectorClient, publicKey, conn := setupIntrospectorClient(t, ctx)
	defer conn.Close()

	vtxoScript := createVtxoScriptWithArkade(bobPubKey, aliceAddr.Signer, publicKey, arkade.ArkadeScriptHash(arkadeScript))

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	bobAddr := arklib.Address{
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

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	bobAddrStr, err := bobAddr.EncodeV0()
	require.NoError(t, err)

	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
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

	var bobOutput *wire.TxOut
	var bobOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(bobAddr.VtxoTapKey)) {
			bobOutput = out
			bobOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, bobOutput)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	// Build transaction with asset packet
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				Outpoint: &wire.OutPoint{
					Hash:  redeemPtx.UnsignedTx.TxHash(),
					Index: bobOutputIndex,
				},
				Tapscript:          tapscript,
				Amount:             bobOutput.Value,
				RevealedTapscripts: []string{hex.EncodeToString(arkadeTapscript)},
			},
		},
		[]*wire.TxOut{
			{
				Value:    bobOutput.Value,
				PkScript: alicePkScript,
			},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	// Add the arkade script field
	err = txutils.SetArkPsbtField(validTx, 0, arkade.ArkadeScriptField, arkadeScript)
	require.NoError(t, err)

	// Add the asset packet to the transaction as an OP_RETURN output
	assetPacketOut, err := assetPacket.TxOut()
	require.NoError(t, err)
	validTx.UnsignedTx.AddTxOut(assetPacketOut)
	validTx.Outputs = append(validTx.Outputs, psbt.POutput{})

	encodedValidTx, err := validTx.B64Encode()
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	signedTx, err := bobWallet.SignTransaction(
		ctx,
		explorer,
		encodedValidTx,
	)
	require.NoError(t, err)

	encodedValidCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, checkpoint := range validCheckpoints {
		encoded, err := checkpoint.B64Encode()
		require.NoError(t, err)
		encodedValidCheckpoints = append(encodedValidCheckpoints, encoded)
	}

	// Submit to introspector - should succeed as the asset introspection opcodes will validate correctly
	signedTx, signedByIntrospectorCheckpoints, err := introspectorClient.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
	require.NoError(t, err)
	require.NotEmpty(t, signedTx)
	require.NotEmpty(t, signedByIntrospectorCheckpoints)

	// Also submit to server
	txid, _, signedByServerCheckpoints, err := grpcAlice.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
	require.NoError(t, err)

	finalCheckpoints := make([]string, 0, len(signedByIntrospectorCheckpoints))
	for i, checkpoint := range signedByServerCheckpoints {
		finalCheckpoint, err := bobWallet.SignTransaction(
			ctx,
			explorer,
			checkpoint,
		)
		require.NoError(t, err)

		// Combine server and introspector checkpoints
		byInterceptorCheckpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(signedByIntrospectorCheckpoints[i]), true)
		require.NoError(t, err)

		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalCheckpoint), true)
		require.NoError(t, err)

		checkpointPtx.Inputs[0].TaprootScriptSpendSig = append(
			checkpointPtx.Inputs[0].TaprootScriptSpendSig,
			byInterceptorCheckpointPtx.Inputs[0].TaprootScriptSpendSig...,
		)

		finalCheckpoint, err = checkpointPtx.B64Encode()
		require.NoError(t, err)

		finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
	}

	err = grpcAlice.FinalizeTx(ctx, txid, finalCheckpoints)
	require.NoError(t, err)
}
