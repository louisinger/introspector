package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/introspector/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	log "github.com/sirupsen/logrus"
)

type Info struct {
	SignerPublicKey string
}

type OffchainTx struct {
	ArkTx       string
	Checkpoints []string
}

type Service interface {
	GetInfo(ctx context.Context) (*Info, error)
	SubmitTx(ctx context.Context, tx OffchainTx) (*OffchainTx, error)
}

type service struct {
	signer    signer
	publicKey string
}

func New(secretKey *btcec.PrivateKey) Service {
	publicKey := hex.EncodeToString(secretKey.PubKey().SerializeCompressed())
	return &service{signer{secretKey}, publicKey}
}

func (s *service) GetInfo(ctx context.Context) (*Info, error) {
	return &Info{SignerPublicKey: s.publicKey}, nil
}

func (s *service) SubmitTx(ctx context.Context, tx OffchainTx) (*OffchainTx, error) {
	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(tx.ArkTx), true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ark PSBT: %w", err)
	}

	// index checkpoints by txid for easy lookup whiloe signing ark transaction
	indexedCheckpoints := make(map[string]*psbt.Packet) // txid => checkpoint psbt
	for _, checkpoint := range tx.Checkpoints {
		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		if err != nil {
			return nil, fmt.Errorf("failed to parse checkpoint PSBT: %w", err)
		}
		indexedCheckpoints[checkpointPtx.UnsignedTx.TxID()] = checkpointPtx
	}

	prevoutFetcher, err := computePrevoutFetcher(arkPtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	// iterate over ark tx inputs
	// skip if the input does not specify any TaprootLeafScript nor any ArkadeScript
	for inputIndex, input := range arkPtx.Inputs {
		if len(input.TaprootLeafScript) == 0 {
			log.WithField("input", inputIndex).Debugf("input does not specify any TaprootLeafScript, skipping")
			continue
		}

		spendingTapscript := input.TaprootLeafScript[0]
		if spendingTapscript == nil {
			log.WithField("input", inputIndex).Debugf("input does not specify any TaprootLeafScript, skipping")
			continue
		}

		arkadeScriptsFields, err := txutils.GetArkPsbtFields(arkPtx, inputIndex, arkade.ArkadeScriptField)
		if err != nil {
			log.Error("unexpected error while getting arkade script fields: %w", err)
			continue
		}

		if len(arkadeScriptsFields) == 0 {
			log.WithField("input", inputIndex).Debugf("input does not specify any ArkadeScript, skipping")
			continue
		}

		// TODO allow multiple scripts ?
		arkadescript := arkadeScriptsFields[0]
		scriptHash := arkade.ArkadeScriptHash(arkadescript)
		expectedPublicKey := arkade.ComputeArkadeScriptPublicKey(s.signer.secretKey.PubKey(), scriptHash)
		expectedPublicKeyXonly := schnorr.SerializePubKey(expectedPublicKey)

		var tapscript scriptlib.MultisigClosure
		valid, err := tapscript.Decode(spendingTapscript.Script)
		if err != nil {
			log.Error("unexpected error while decoding tapscript: %w", err)
			continue
		}
		if !valid {
			log.WithField("input", inputIndex).Debugf("spendingtapscript is not a MultisigClosure, skipping")
			continue
		}

		found := false

		for _, pubkey := range tapscript.PubKeys {
			xonly := schnorr.SerializePubKey(pubkey)
			if bytes.Equal(xonly, expectedPublicKeyXonly) {
				found = true
				break
			}
		}

		if !found {
			log.Warnf("tweaked arkade script public key not found in tapscript: %x", expectedPublicKeyXonly)
			continue
		}

		arkadeScriptWitnessFields, err := txutils.GetArkPsbtFields(arkPtx, inputIndex, arkade.ArkadeScriptWitnessField)
		if err != nil {
			log.Error("unexpected error while getting arkade script witness fields: %w", err)
			continue
		}

		arkadeScriptWitness := make(wire.TxWitness, 0)
		if len(arkadeScriptWitnessFields) > 0 {
			arkadeScriptWitness = arkadeScriptWitnessFields[0]
		}

		log.Infof("executing arkade script: %x", arkadescript)

		if err := executeArkadeScript(arkadescript, arkPtx.UnsignedTx, prevoutFetcher, inputIndex, arkadeScriptWitness); err != nil {
			log.Infof("execution of %x failed", arkadescript)
			return nil, fmt.Errorf("failed to execute arkade script: %w", err)
		}
		log.Infof("execution of %x succeeded", arkadescript)

		if err := s.signer.signInput(arkPtx, inputIndex, scriptHash, prevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		// search for checkpoint
		inputTxid := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.Hash.String()
		checkpointPtx, ok := indexedCheckpoints[inputTxid]
		if !ok {
			return nil, fmt.Errorf("checkpoint not found for input %d", inputIndex)
		}

		checkpointPrevoutFetcher, err := computePrevoutFetcher(checkpointPtx)
		if err != nil {
			return nil, fmt.Errorf("failed to create prevout fetcher for checkpoint: %w", err)
		}

		if err := s.signer.signInput(checkpointPtx, 0, scriptHash, checkpointPrevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign checkpoint input %d: %w", inputIndex, err)
		}
	}

	signedArkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode ark tx: %w", err)
	}

	signedCheckpointTxs := make([]string, 0)
	for _, checkpoint := range indexedCheckpoints {
		signedCheckpointTx, err := checkpoint.B64Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode checkpoint tx: %w", err)
		}
		signedCheckpointTxs = append(signedCheckpointTxs, signedCheckpointTx)
	}

	return &OffchainTx{
		ArkTx:       signedArkTx,
		Checkpoints: signedCheckpointTxs,
	}, nil
}

func executeArkadeScript(
	arkScript []byte,
	spendingTx *wire.MsgTx,
	prevoutFetcher txscript.PrevOutputFetcher,
	inputIndex int,
	arkScriptStack wire.TxWitness,
) error {
	engine, err := arkade.NewEngine(
		arkScript,
		spendingTx,
		inputIndex,
		txscript.StandardVerifyFlags,
		txscript.NewSigCache(100),
		txscript.NewTxSigHashes(spendingTx, prevoutFetcher),
		0, // TODO : add input amount if need CHECKSIG in custom script?
		prevoutFetcher,
	)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	if len(arkScriptStack) > 0 {
		engine.SetStack(arkScriptStack)
	}

	if err := engine.Execute(); err != nil {
		return fmt.Errorf("failed to execute custom script: %w", err)
	}

	return nil
}

// TODO : do not rely on witness utxo to compute the prevout fetcher
func computePrevoutFetcher(ptx *psbt.Packet) (txscript.PrevOutputFetcher, error) {
	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for index, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("witness utxo is nil")
		}

		if len(ptx.UnsignedTx.TxIn) <= index {
			return nil, fmt.Errorf("input index out of range")
		}

		outpoint := ptx.UnsignedTx.TxIn[index].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	return txscript.NewMultiPrevOutFetcher(prevouts), nil
}
