mod common;

use common::{Asset, Keypair, Utxo, merge_digest, utxo_commitment};

use usernode_circuits::bn254::Field;
use usernode_circuits::prover::{
    MergeInputEnc, SchnorrEnc, UtxoEnc, encode_merge_privates, init_default_circuits, prove,
};

#[allow(clippy::too_many_arguments)]
fn build_merge_inputs(
    sender: &Keypair,
    in0_tokens: [Field; 4],
    in0_amounts: [Field; 4],
    in0_salt: Field,
    in1_tokens: [Field; 4],
    in1_amounts: [Field; 4],
    in1_salt: Field,
    out_tokens: [Field; 4],
    out_amounts: [Field; 4],
    out_salt: Field,
) -> (MergeInputEnc, [u8; 32]) {
    let sender_pkx = sender.pk_x_bytes();
    let sender_pky = sender.pk_y_bytes();
    let sender_pkx_field = Field::from_bytes(sender_pkx);

    let out_note = Utxo {
        assets: [
            Asset {
                token: out_tokens[0],
                amount: out_amounts[0],
            },
            Asset {
                token: out_tokens[1],
                amount: out_amounts[1],
            },
            Asset {
                token: out_tokens[2],
                amount: out_amounts[2],
            },
            Asset {
                token: out_tokens[3],
                amount: out_amounts[3],
            },
        ],
        recipient_pk_x: sender_pkx_field,
        salt: out_salt,
    };
    let out_commit = utxo_commitment(&out_note);
    let msg32 = merge_digest(sender_pkx_field, out_commit);

    let enc = MergeInputEnc {
        schnorr: SchnorrEnc {
            pk_x: sender_pkx,
            pk_y: sender_pky,
            sig64: [0u8; 64],
            msg32,
        },
        in0: UtxoEnc {
            assets_tokens: in0_tokens,
            assets_amounts: in0_amounts,
            recipient_pk_x: sender_pkx,
            salt: in0_salt,
        },
        in1: UtxoEnc {
            assets_tokens: in1_tokens,
            assets_amounts: in1_amounts,
            recipient_pk_x: sender_pkx,
            salt: in1_salt,
        },
        out: UtxoEnc {
            assets_tokens: out_tokens,
            assets_amounts: out_amounts,
            recipient_pk_x: sender_pkx,
            salt: out_salt,
        },
    };

    (enc, msg32)
}

fn expect_merge_err(enc: &MergeInputEnc) {
    let privates = encode_merge_privates(enc);
    let result = prove("utxo_merge", &privates);
    assert!(result.is_err(), "expected proving failure");
}

#[test]
fn bad_signature_rejected() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([1u8; 32]);
    let attacker = Keypair::from_seed([2u8; 32]);

    let in_tokens = [Field::from(7), Field::zero(), Field::zero(), Field::zero()];
    let in0_amounts = [Field::from(40), Field::zero(), Field::zero(), Field::zero()];
    let in1_amounts = [Field::from(60), Field::zero(), Field::zero(), Field::zero()];
    let out_amounts = [
        Field::from(100),
        Field::zero(),
        Field::zero(),
        Field::zero(),
    ];

    let (mut enc, msg32) = build_merge_inputs(
        &sender,
        in_tokens,
        in0_amounts,
        Field::from(11u128),
        in_tokens,
        in1_amounts,
        Field::from(22u128),
        in_tokens,
        out_amounts,
        Field::from(33u128),
    );

    enc.schnorr.sig64 = attacker.sign(msg32);
    expect_merge_err(&enc);
}

#[test]
fn bad_msg32_rejected() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([3u8; 32]);

    let in_tokens = [Field::from(7), Field::zero(), Field::zero(), Field::zero()];
    let in0_amounts = [Field::from(40), Field::zero(), Field::zero(), Field::zero()];
    let in1_amounts = [Field::from(60), Field::zero(), Field::zero(), Field::zero()];
    let out_amounts = [
        Field::from(100),
        Field::zero(),
        Field::zero(),
        Field::zero(),
    ];

    let (mut enc, mut msg32) = build_merge_inputs(
        &sender,
        in_tokens,
        in0_amounts,
        Field::from(44u128),
        in_tokens,
        in1_amounts,
        Field::from(55u128),
        in_tokens,
        out_amounts,
        Field::from(66u128),
    );

    msg32[0] ^= 0x42;
    enc.schnorr.msg32 = msg32;
    enc.schnorr.sig64 = sender.sign(msg32);
    expect_merge_err(&enc);
}

#[test]
fn mismatched_input_tokens_rejected() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([5u8; 32]);

    let in0_tokens = [
        Field::from(7),
        Field::from(0),
        Field::from(0),
        Field::from(1),
    ];
    let in1_tokens = [
        Field::from(7),
        Field::from(0),
        Field::from(0),
        Field::from(2),
    ];
    let in0_amounts = [
        Field::from(10),
        Field::from(0),
        Field::from(0),
        Field::from(1),
    ];
    let in1_amounts = [
        Field::from(20),
        Field::from(0),
        Field::from(0),
        Field::from(2),
    ];
    let out_tokens = [
        Field::from(7),
        Field::from(0),
        Field::from(0),
        Field::from(1),
    ];
    let out_amounts = [
        Field::from(30),
        Field::from(0),
        Field::from(0),
        Field::from(3),
    ];

    let (mut enc, msg32) = build_merge_inputs(
        &sender,
        in0_tokens,
        in0_amounts,
        Field::from(1u128),
        in1_tokens,
        in1_amounts,
        Field::from(2u128),
        out_tokens,
        out_amounts,
        Field::from(3u128),
    );

    enc.schnorr.sig64 = sender.sign(msg32);
    expect_merge_err(&enc);
}

#[test]
fn output_not_sum_rejected() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([7u8; 32]);

    let in_tokens = [Field::from(7), Field::zero(), Field::zero(), Field::zero()];
    let in0_amounts = [Field::from(40), Field::zero(), Field::zero(), Field::zero()];
    let in1_amounts = [Field::from(60), Field::zero(), Field::zero(), Field::zero()];
    let out_amounts = [Field::from(99), Field::zero(), Field::zero(), Field::zero()];

    let (mut enc, msg32) = build_merge_inputs(
        &sender,
        in_tokens,
        in0_amounts,
        Field::from(9u128),
        in_tokens,
        in1_amounts,
        Field::from(10u128),
        in_tokens,
        out_amounts,
        Field::from(11u128),
    );

    enc.schnorr.sig64 = sender.sign(msg32);
    expect_merge_err(&enc);
}
