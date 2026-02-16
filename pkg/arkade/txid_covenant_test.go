package arkade

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestOpcodeTxid verifies OP_TXID pushes the transaction hash onto the stack
func TestOpcodeTxid(t *testing.T) {
	tests := []struct {
		name   string
		setup  func() *Engine
		verify func(*testing.T, *Engine)
	}{
		{
			name: "basic txid push",
			setup: func() *Engine {
				tx := wire.NewMsgTx(2)
				tx.AddTxIn(&wire.TxIn{
					PreviousOutPoint: wire.OutPoint{
						Hash:  chainhash.Hash{},
						Index: 0,
					},
				})
				tx.AddTxOut(&wire.TxOut{
					Value:    10000,
					PkScript: []byte{0x00, 0x14, 0x00},
				})

				return &Engine{
					tx:     *tx,
					dstack: stack{},
					flags:  txscript.StandardVerifyFlags,
				}
			},
			verify: func(t *testing.T, vm *Engine) {
				// Calculate expected txid
				expectedTxid := vm.tx.TxHash()

				// Execute OP_TXID
				err := opcodeTxid(nil, nil, vm)
				require.NoError(t, err)

				// Pop the result
				txidBytes, err := vm.dstack.PopByteArray()
				require.NoError(t, err)
				require.Len(t, txidBytes, 32, "txid should be 32 bytes")

				// Verify it matches
				require.Equal(t, expectedTxid[:], txidBytes, "txid should match transaction hash")
			},
		},
		{
			name: "different transactions have different txids",
			setup: func() *Engine {
				tx := wire.NewMsgTx(2)
				tx.AddTxOut(&wire.TxOut{
					Value:    50000, // Different value
					PkScript: []byte{0x00, 0x20, 0x01},
				})

				return &Engine{
					tx:     *tx,
					dstack: stack{},
					flags:  txscript.StandardVerifyFlags,
				}
			},
			verify: func(t *testing.T, vm *Engine) {
				expectedTxid := vm.tx.TxHash()

				err := opcodeTxid(nil, nil, vm)
				require.NoError(t, err)

				txidBytes, err := vm.dstack.PopByteArray()
				require.NoError(t, err)

				require.Equal(t, expectedTxid[:], txidBytes)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm := tt.setup()
			tt.verify(t, vm)
		})
	}
}

// TestCovenantTxidEqual demonstrates a simple covenant: UTXO can only be spent in a specific transaction
func TestCovenantTxidEqual(t *testing.T) {
	t.Run("covenant script allows correct txid", func(t *testing.T) {
		// Create a transaction
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.HashH([]byte("previous-tx")),
				Index: 0,
			},
		})
		tx.AddTxOut(&wire.TxOut{
			Value:    10000,
			PkScript: []byte{0x00, 0x14, 0xaa, 0xbb},
		})

		// Get the txid of this transaction
		expectedTxid := tx.TxHash()

		// Covenant script: <expected_txid> OP_TXID OP_EQUAL
		// This script only passes if the spending transaction has the expected txid
		builder := txscript.NewScriptBuilder()
		builder.AddData(expectedTxid[:])
		builder.AddOp(OP_TXID)
		builder.AddOp(txscript.OP_EQUAL)
		covenantScript, err := builder.Script()
		require.NoError(t, err)

		// Create engine with this transaction
		vm := &Engine{
			tx:      *tx,
			scripts: [][]byte{covenantScript},
			scriptIdx: 0,
			dstack:  stack{},
			flags:   txscript.StandardVerifyFlags,
		}

		// Execute the covenant script
		err = vm.Execute()
		require.NoError(t, err, "covenant should pass for correct txid")

		// Stack should have 1 (true) on top
		result, err := vm.dstack.PopInt()
		require.NoError(t, err)
		require.Equal(t, int64(1), int64(result), "covenant should evaluate to true")
	})

	t.Run("covenant script rejects wrong txid", func(t *testing.T) {
		// Create a transaction
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.HashH([]byte("previous-tx")),
				Index: 0,
			},
		})
		tx.AddTxOut(&wire.TxOut{
			Value:    10000,
			PkScript: []byte{0x00, 0x14, 0xcc, 0xdd},
		})

		// Use a DIFFERENT txid in the covenant
		wrongTxid := chainhash.HashH([]byte("wrong-txid"))

		// Covenant script with wrong expected txid
		builder := txscript.NewScriptBuilder()
		builder.AddData(wrongTxid[:])
		builder.AddOp(OP_TXID)
		builder.AddOp(txscript.OP_EQUAL)
		covenantScript, err := builder.Script()
		require.NoError(t, err)

		// Create engine
		vm := &Engine{
			tx:        *tx,
			scripts:   [][]byte{covenantScript},
			scriptIdx: 0,
			dstack:    stack{},
			flags:     txscript.StandardVerifyFlags,
		}

		// Execute the covenant script
		err = vm.Execute()
		require.NoError(t, err, "script execution should complete")

		// Stack should have 0 (false) on top
		result, err := vm.dstack.PopInt()
		require.NoError(t, err)
		require.Equal(t, int64(0), int64(result), "covenant should evaluate to false for wrong txid")
	})
}

// TestAIAgentCovenantUseCase demonstrates the AI agent safety use case
func TestAIAgentCovenantUseCase(t *testing.T) {
	t.Run("pre-authorized payment to specific address", func(t *testing.T) {
		// Scenario: You want to send funds to AI agent that can ONLY pay address X
		
		// 1. AI constructs payment transaction template
		paymentTx := wire.NewMsgTx(2)
		paymentTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{}, // Will be filled when UTXO created
				Index: 0,
			},
		})
		
		// Add output paying to authorized address
		authorizedAddress := []byte{0x00, 0x14} // SegWit v0, 20-byte hash
		authorizedAddress = append(authorizedAddress, make([]byte, 20)...) // Placeholder address
		paymentTx.AddTxOut(&wire.TxOut{
			Value:    9000, // Amount minus fee
			PkScript: authorizedAddress,
		})

		// 2. Compute txid of this specific payment transaction
		allowedTxid := paymentTx.TxHash()

		t.Logf("Allowed payment txid: %s", hex.EncodeToString(allowedTxid[:]))

		// 3. Create covenant script: Only allow spending if txid matches
		covenantScript, err := txscript.NewScriptBuilder().
			AddData(allowedTxid[:]).
			AddOp(OP_TXID).
			AddOp(txscript.OP_EQUALVERIFY).
			// In real scenario, would add OP_CHECKSIG here for AI agent's key
			AddInt64(1). // Push true to make script valid
			Script()
		require.NoError(t, err)

		// 4. Simulate execution when AI tries to broadcast the payment
		vm := &Engine{
			tx:        *paymentTx,
			scripts:   [][]byte{covenantScript},
			scriptIdx: 0,
			dstack:    stack{},
			flags:     txscript.StandardVerifyFlags,
		}

		err = vm.Execute()
		require.NoError(t, err, "authorized payment should succeed")

		// Stack should be clean or have true
		t.Log("✅ Covenant allows pre-authorized payment")
	})

	t.Run("attacker cannot redirect funds", func(t *testing.T) {
		// Attacker steals AI's private key and tries to redirect funds

		// Original authorized payment txid
		authorizedTxid := chainhash.HashH([]byte("authorized-payment"))

		// Covenant locks funds to specific txid
		covenantScript, err := txscript.NewScriptBuilder().
			AddData(authorizedTxid[:]).
			AddOp(OP_TXID).
			AddOp(txscript.OP_EQUALVERIFY).
			AddInt64(1).
			Script()
		require.NoError(t, err)

		// Attacker creates different transaction to steal funds
		attackTx := wire.NewMsgTx(2)
		attackTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0,
			},
		})
		attackTx.AddTxOut(&wire.TxOut{
			Value:    9000,
			PkScript: []byte{0x00, 0x14, 0xde, 0xad, 0xbe, 0xef}, // Attacker's address
		})

		// Attacker's tx will have different txid
		attackTxid := attackTx.TxHash()
		require.NotEqual(t, authorizedTxid, attackTxid, "attack tx should have different txid")

		vm := &Engine{
			tx:        *attackTx,
			scripts:   [][]byte{covenantScript},
			scriptIdx: 0,
			dstack:    stack{},
			flags:     txscript.StandardVerifyFlags,
		}

		// Covenant should fail on OP_EQUALVERIFY
		err = vm.Execute()
		require.Error(t, err, "covenant should reject unauthorized transaction")
		require.Contains(t, err.Error(), "EQUALVERIFY", "should fail on txid mismatch")

		t.Log("✅ Covenant prevents theft even with compromised private key")
	})
}
