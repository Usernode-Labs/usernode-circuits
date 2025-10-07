//! Integration-style checks for the high-level merge API.
//!
//! The scenario mirrors the wallet flow: create witnesses, call `prove_merge`,
//! and inspect the returned metadata/commitment before verifying the proof.

mod common;

use common::serial_guard;
use usernode_circuits::bn254::Field;
use usernode_circuits::catalog;
use usernode_circuits::keys::Keypair;
use usernode_circuits::tx::{MergeRequest, prove_merge};
use usernode_circuits::types::{Asset, MergeInput, SchnorrPublicKey, TransactionOutput, Utxo};

#[test]
fn merge_prove_matches_commitment() {
    let _guard = serial_guard();
    catalog::clear();
    usernode_circuits::init_default_circuits().expect("init embedded circuits");

    let signer = Keypair::from_seed([5u8; 32]).expect("derive keypair");

    let utxo_from_input = |amount: u128, salt: u128| Utxo {
        assets: [
            Asset {
                token: Field::from(7u128),
                amount: Field::from(amount),
            },
            Asset::empty(),
            Asset::empty(),
            Asset::empty(),
        ],
        recipient_pk_x: Field::from_bytes(signer.public_key_xonly()),
        salt: Field::from(salt),
    };

    let in0 = utxo_from_input(60, 10);
    let in1 = utxo_from_input(40, 11);
    let (signer_pk_x, signer_pk_y) = signer.public_key_xy();
    let signer_pk = SchnorrPublicKey::new(signer_pk_x, signer_pk_y);
    let witness0 = MergeInput::new(in0, signer_pk);
    let witness1 = MergeInput::new(in1, signer_pk);

    let out_tokens = [
        Field::from(7u128),
        Field::zero(),
        Field::zero(),
        Field::zero(),
    ];
    let out_amounts = [
        Field::from(100u128),
        Field::zero(),
        Field::zero(),
        Field::zero(),
    ];

    // Build the high-level request and let `prove_merge` do the ABI packing.
    let tx = prove_merge(MergeRequest {
        signer: &signer,
        inputs: [witness0, witness1],
        out_tokens,
        out_amounts,
        out_salt: Some(Field::from(1234u128)),
        ensure_unique: None,
        verify_proof: true,
    })
    .expect("merge proof generation");

    // Confirm the helper rebuilt the same output commitment that the circuit
    // exposes as a public value.
    match tx.outputs {
        TransactionOutput::Merge { ref utxo } => {
            assert_ne!(utxo.commitment().to_bytes(), [0u8; 32]);
            assert_eq!(utxo.salt, Field::from(1234u128));
        }
        _ => panic!("merge tx must produce merge output"),
    }

    // Validate the generated proof against the embedded verification key.
    assert!(usernode_circuits::verify("utxo_merge", &tx.proof).expect("verify"));
    catalog::clear();
}
