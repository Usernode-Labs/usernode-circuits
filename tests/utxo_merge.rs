mod common;

use common::{Asset, Keypair, Utxo, merge_digest, utxo_commitment};

use usernode_circuits::bn254::Field;
use usernode_circuits::prover::{
    MergeInputEnc, SchnorrEnc, UtxoEnc, encode_merge_privates, init_default_circuits, prove, verify,
};

#[test]
fn prove_and_verify_utxo_merge() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([42u8; 32]);
    let sender_pkx_bytes = sender.pk_x_bytes();
    let sender_pky_bytes = sender.pk_y_bytes();
    let sender_pkx_field = Field::from_bytes(sender_pkx_bytes);

    let in_tokens = [
        Field::from(7u128),
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let in0_amounts = [
        Field::from(40u128),
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let in1_amounts = [
        Field::from(60u128),
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let in0_salt = Field::from(111u128);
    let in1_salt = Field::from(222u128);

    let out_amounts = [
        Field::from(100u128),
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let out_salt = Field::from(333u128);

    let out_utxo = Utxo {
        assets: [
            Asset {
                token: in_tokens[0],
                amount: out_amounts[0],
            },
            Asset {
                token: in_tokens[1],
                amount: out_amounts[1],
            },
            Asset {
                token: in_tokens[2],
                amount: out_amounts[2],
            },
            Asset {
                token: in_tokens[3],
                amount: out_amounts[3],
            },
        ],
        recipient_pk_x: sender_pkx_field,
        salt: out_salt,
    };

    let out_commit = utxo_commitment(&out_utxo);
    let msg32 = merge_digest(sender_pkx_field, out_commit);
    let signature = sender.sign(msg32);
    assert!(
        sender.verify(msg32, signature),
        "schnorr signature must verify"
    );

    let merge_enc = MergeInputEnc {
        schnorr: SchnorrEnc {
            pk_x: sender_pkx_bytes,
            pk_y: sender_pky_bytes,
            sig64: signature,
            msg32,
        },
        in0: UtxoEnc {
            assets_tokens: in_tokens,
            assets_amounts: in0_amounts,
            recipient_pk_x: sender_pkx_bytes,
            salt: in0_salt,
        },
        in1: UtxoEnc {
            assets_tokens: in_tokens,
            assets_amounts: in1_amounts,
            recipient_pk_x: sender_pkx_bytes,
            salt: in1_salt,
        },
        out: UtxoEnc {
            assets_tokens: in_tokens,
            assets_amounts: out_amounts,
            recipient_pk_x: sender_pkx_bytes,
            salt: out_salt,
        },
    };

    let privates = encode_merge_privates(&merge_enc);
    let proof = prove("utxo_merge", &privates).expect("prove utxo_merge");
    assert!(verify("utxo_merge", &proof).expect("verify utxo_merge"));
}
