#![deny(clippy::all)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::module_name_repetitions)]

pub mod artifacts;
pub mod batch;
pub mod bn254;
pub mod catalog;
pub mod keys;
pub mod poseidon2;
pub mod prover;
pub mod tx;
pub mod types;

pub use prover::{
    MergeInputEnc, SchnorrEnc, SpendInputEnc, TransferEnc, UtxoEnc, encode_merge_privates,
    encode_spend_privates, get_circuit, init_circuit_from_artifacts, init_default_circuits,
    init_embedded_catalog, merge_batch_h2, merge_batch_h2_by_name, merge_proofs_by_name, prove,
    prove_with_abi, prove_with_all_inputs, prove_with_priv_and_pub, public_outputs, regenerate_vk,
    verify,
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
    Asset, MAX_ASSETS, MergeTx, MerklePathNode, SpendTx, TransactionOutput, Utxo, UtxoCommitment,
    UtxoInclusionWitness, UtxoTransaction,
};
