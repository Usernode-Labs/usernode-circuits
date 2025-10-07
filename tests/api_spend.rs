//! Integration-style checks for the high-level spend API.
//!
//! The test exercises the complete flow from `SpendRequest` through ABI
//! packing, Barretenberg proving, and hash reconstruction without touching the
//! wider node code base.

mod common;

use common::serial_guard;
use usernode_circuits::bn254::Field;
use usernode_circuits::catalog;
use usernode_circuits::keys::Keypair;
use usernode_circuits::tx::{SpendRequest, prove_spend};
use usernode_circuits::types::{Asset, SchnorrPublicKey, SpendInput, TransactionOutput, Utxo};

#[test]
fn spend_prove_matches_commitments() {
    let _guard = serial_guard();
    catalog::clear();
    usernode_circuits::init_default_circuits().expect("init embedded circuits");

    let signer = Keypair::from_seed([7u8; 32]).expect("derive keypair");
    let recipient = Keypair::from_seed([9u8; 32]).expect("derive recipient");

    let input_utxo = Utxo {
        assets: [
            Asset {
                token: Field::from(7u128),
                amount: Field::from(100u128),
            },
            Asset::empty(),
            Asset::empty(),
            Asset::empty(),
        ],
        recipient_pk_x: Field::from_bytes(signer.public_key_xonly()),
        salt: Field::from(1111u128),
    };
    let (signer_pk_x, signer_pk_y) = signer.public_key_xy();
    let input = SpendInput::new(
        input_utxo.clone(),
        SchnorrPublicKey::new(signer_pk_x, signer_pk_y),
    );

    let transfer_token = Field::from(7u128);
    let transfer_amount = Field::from(40u128);
    let fee_amount = Field::from(2u128);

    // Build the high-level request and let `prove_spend` translate it into the
    // Noir ABI + witness map.
    let tx = prove_spend(SpendRequest {
        signer: &signer,
        recipient_pk_x: recipient.public_key_xonly(),
        input,
        transfer_token,
        transfer_amount,
        fee_amount,
        ensure_unique: None,
        verify_proof: true,
    })
    .expect("spend proof generation");

    // The returned outputs mirror what the circuit commits to. Sanity check
    // that the commitments look well-formed (non-zero).
    match tx.outputs {
        TransactionOutput::Spend {
            ref receiver,
            ref remainder,
        } => {
            assert_ne!(receiver.commitment().to_bytes(), [0u8; 32]);
            assert_ne!(remainder.commitment().to_bytes(), [0u8; 32]);
        }
        _ => panic!("spend tx must produce spend outputs"),
    }

    assert_eq!(tx.transfer_token, transfer_token);
    assert_eq!(tx.transfer_amount, transfer_amount);
    assert_eq!(tx.fee_amount, fee_amount);
    assert_eq!(tx.input.signer.pk_x_bytes(), signer.public_key_xonly());
    // Finally confirm the proof verifies against the embedded verification key.
    assert!(usernode_circuits::verify("utxo_spend", &tx.proof).expect("verify"));

    catalog::clear();
}
