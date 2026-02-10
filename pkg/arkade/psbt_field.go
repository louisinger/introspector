package arkade

import (
	"bytes"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

var (
	ArkadeScript        = []byte("arkadescript")
	ArkadeScriptWitness = []byte("arkadescriptwitness")
	AssetPacket         = []byte("assetpacket")
)

var ArkadeScriptField txutils.ArkPsbtFieldCoder[[]byte] = &arkadeScriptField{}
var ArkadeScriptWitnessField txutils.ArkPsbtFieldCoder[wire.TxWitness] = &arkadeScriptWitnessField{}
var AssetPacketField txutils.ArkPsbtFieldCoder[[]byte] = &assetPacketField{}

type arkadeScriptField struct{}

func (f *arkadeScriptField) Encode(data []byte) (*psbt.Unknown, error) {
	return &psbt.Unknown{
		Key:   makeArkPsbtKey(ArkadeScript),
		Value: data,
	}, nil
}

func (f *arkadeScriptField) Decode(unknownField *psbt.Unknown) (*[]byte, error) {
	if !containsArkPsbtKey(unknownField, ArkadeScript) {
		return nil, nil
	}

	return &unknownField.Value, nil
}

type arkadeScriptWitnessField struct{}

func (c arkadeScriptWitnessField) Encode(witness wire.TxWitness) (*psbt.Unknown, error) {
	var witnessBytes bytes.Buffer

	err := psbt.WriteTxWitness(&witnessBytes, witness)
	if err != nil {
		return nil, err
	}

	return &psbt.Unknown{
		Key:   makeArkPsbtKey(ArkadeScriptWitness),
		Value: witnessBytes.Bytes(),
	}, nil
}

func (c arkadeScriptWitnessField) Decode(unknown *psbt.Unknown) (*wire.TxWitness, error) {
	if !containsArkPsbtKey(unknown, ArkadeScriptWitness) {
		return nil, nil
	}

	witness, err := txutils.ReadTxWitness(unknown.Value)
	if err != nil {
		return nil, err
	}

	return &witness, nil
}

func makeArkPsbtKey(keyData []byte) []byte {
	return append([]byte{txutils.ArkPsbtFieldKeyType}, keyData...)
}

type assetPacketField struct{}

func (f *assetPacketField) Encode(data []byte) (*psbt.Unknown, error) {
	return &psbt.Unknown{
		Key:   makeArkPsbtKey(AssetPacket),
		Value: data,
	}, nil
}

func (f *assetPacketField) Decode(unknownField *psbt.Unknown) (*[]byte, error) {
	if !containsArkPsbtKey(unknownField, AssetPacket) {
		return nil, nil
	}

	return &unknownField.Value, nil
}

func containsArkPsbtKey(unknownField *psbt.Unknown, keyFieldName []byte) bool {
	if len(unknownField.Key) == 0 {
		return false
	}

	return bytes.Contains(unknownField.Key, keyFieldName)
}
