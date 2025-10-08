#![deny(clippy::all)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::module_name_repetitions)]

pub mod artifacts;
mod barretenberg;
pub mod batch;
pub mod bn254;
pub mod catalog;
pub mod field;
pub mod keys;
pub mod poseidon2;
pub mod prover;
pub mod tx;
pub mod types;

pub use field::CircuitFieldElement;
pub use prover::{
    MergeInputEnc, SchnorrEnc, SpendInputEnc, TransferEnc, UtxoEnc, encode_merge_privates,
    encode_spend_privates, fetch_batch_public_inputs, get_circuit, get_key_id, get_vk_bytes_by_id,
    get_vk_hash_by_id, init_circuit_from_artifacts, init_default_circuits, init_embedded_catalog,
    merge_batch_h2_by_id, prove, prove_with_abi, prove_with_all_inputs, prove_with_priv_and_pub,
    public_outputs, regenerate_vk, verify,
};

pub use batch::{
    BindingBlock, BindingLeaf, CandidateLeaf, CandidateWithRecord, LeafRecord, canonical_root_even,
    plan_block, plan_block_from_candidates, validate_and_plan_block,
};
pub use keys::Keypair;
pub use tx::{
    MergeRequest, SpendRequest, merge_commitment, prove_merge, prove_spend, spend_commitments,
};
pub use types::{
    Asset, MAX_ASSETS, MergeInput, MergeTx, SchnorrPublicKey, SpendInput, SpendTx,
    TransactionOutput, Utxo, UtxoTransaction,
};
