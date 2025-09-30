//! Shared domain types used by the proving helpers and the high level API.
//!
//! These structs are intentionally small mirrors of the data the Noir circuits
//! work with (UTXOs, commitments, transactions). Keeping them in one module
//! allows the rest of the crate to talk about transactions without referencing
//! Noir-specific concepts directly.

use crate::bn254::Field;
use crate::poseidon2::{hash_merge_leaf, hash_spend_leaf, hash10};

/// Fixed number of asset slots enforced by the Noir circuits.
pub const MAX_ASSETS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asset {
    /// Token identifier committed inside the circuit (BN254 field).
    pub token: Field,
    /// Amount aligned with the same slot.
    pub amount: Field,
}

impl Asset {
    /// Convenience constructor for a zero-valued asset slot.
    pub fn empty() -> Self {
        Self {
            token: Field::from(0u128),
            amount: Field::from(0u128),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    /// Fixed-width asset vector (four slots, matching the Noir circuit).
    pub assets: [Asset; MAX_ASSETS],
    /// X-only public key of the recipient – stored directly in the commitment.
    pub recipient_pk_x: Field,
    /// Random salt combined with the assets/public key in the Poseidon2 hash.
    pub salt: Field,
}

impl Utxo {
    /// Compute the Poseidon2 commitment used by the circuits and Merkle tree.
    pub fn commitment(&self) -> Field {
        hash10([
            self.recipient_pk_x,
            self.assets[0].token,
            self.assets[0].amount,
            self.assets[1].token,
            self.assets[1].amount,
            self.assets[2].token,
            self.assets[2].amount,
            self.assets[3].token,
            self.assets[3].amount,
            self.salt,
        ])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UtxoCommitment(pub [u8; 32]);

impl UtxoCommitment {
    /// Construct a raw commitment from a UTXO by hashing it.
    pub fn compute(utxo: &Utxo) -> Self {
        Self(utxo.commitment().to_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerklePathNode {
    /// Sibling hash in the path.
    pub sibling: Field,
    /// Whether the sibling sits on the left-hand side.
    pub is_left: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoInclusionWitness {
    /// Commitment of the UTXO (matches the Merkle tree leaf).
    pub commitment: UtxoCommitment,
    /// Index of the leaf inside the tree.
    pub index: u64,
    /// Merkle authentication path from the leaf to the root.
    pub path: Vec<MerklePathNode>,
    /// Full UTXO payload (needed to compute private inputs).
    pub utxo: Utxo,
}

impl UtxoInclusionWitness {
    /// Convenience helper for tests that do not use an actual Merkle tree.
    pub fn dummy(utxo: Utxo) -> Self {
        Self {
            commitment: UtxoCommitment::compute(&utxo),
            index: 0,
            path: Vec::new(),
            utxo,
        }
    }
}

// Variants intentionally carry the full UTXO data; boxing would only add heap
// churn in callers that already stack-allocate these records.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionOutput {
    /// Spend transaction: two outputs (receiver + remainder/change).
    Spend { receiver: Utxo, remainder: Utxo },
    /// Merge transaction: single consolidated output.
    Merge { utxo: Utxo },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendTx {
    /// Inclusion witness for the consumed UTXO.
    pub input: UtxoInclusionWitness,
    /// Outputs reconstructed from the private inputs.
    pub outputs: TransactionOutput,
    /// Commitments expected by the circuit (receiver and remainder).
    pub expected_out_commits: [Field; 2],
    /// Barretenberg proof bytes.
    pub proof: Vec<u8>,
    /// Public key x-coordinate used in the digest and Schnorr verification.
    pub sender_pk_x: Field,
    /// Token being transferred.
    pub transfer_token: Field,
    /// Amount being transferred to the receiver.
    pub transfer_amount: Field,
    /// Fee paid in slot 0 of the remainder output.
    pub fee_amount: Field,
    /// Schnorr signature produced by the signer.
    pub signature: [u8; 64],
    /// Canonical 32-byte message hashed inside the circuit.
    pub msg32: [u8; 32],
    /// Poseidon2 digest corresponding to `msg32` (full field element form).
    pub digest: Field,
}

impl SpendTx {
    /// Recompute the leaf hash enforced by the circuit for Merkle trees/batches.
    pub fn leaf_hash(&self) -> Field {
        match &self.outputs {
            TransactionOutput::Spend {
                receiver: _,
                remainder: _,
            } => hash_spend_leaf(
                Field::from_bytes(self.input.commitment.0),
                self.expected_out_commits[0],
                self.expected_out_commits[1],
                self.transfer_token,
                self.transfer_amount,
                self.fee_amount,
            ),
            TransactionOutput::Merge { .. } => {
                unreachable!("spend tx outputs must be spend variant")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeTx {
    /// Inclusion witnesses for both consumed UTXOs.
    pub inputs: [UtxoInclusionWitness; 2],
    /// Output reconstructed from the private inputs.
    pub outputs: TransactionOutput,
    /// Commitment expected by the merge circuit.
    pub expected_out_commit: Field,
    /// Barretenberg proof bytes.
    pub proof: Vec<u8>,
    /// Public key x-coordinate used in the digest and Schnorr verification.
    pub sender_pk_x: Field,
    /// Schnorr signature produced by the signer.
    pub signature: [u8; 64],
    /// Canonical 32-byte message hashed inside the circuit.
    pub msg32: [u8; 32],
    /// Poseidon2 digest corresponding to `msg32` (full field element form).
    pub digest: Field,
}

impl MergeTx {
    /// Recompute the leaf hash enforced by the circuit for Merkle trees/batches.
    pub fn leaf_hash(&self) -> Field {
        match &self.outputs {
            TransactionOutput::Merge { utxo: _ } => hash_merge_leaf(
                Field::from_bytes(self.inputs[0].commitment.0),
                Field::from_bytes(self.inputs[1].commitment.0),
                self.expected_out_commit,
            ),
            TransactionOutput::Spend { .. } => {
                unreachable!("merge tx outputs must be merge variant")
            }
        }
    }
}

// The outer wrapper mirrors the historic API and keeps transaction structs on
// the stack for ergonomic pattern matching.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UtxoTransaction {
    /// Spend transaction wrapper.
    Spend(SpendTx),
    /// Merge transaction wrapper.
    Merge(MergeTx),
}
