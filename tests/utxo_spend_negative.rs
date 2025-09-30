mod common;

use common::{Asset, Keypair, Utxo, spend_digest, utxo_commitment};

use usernode_circuits::bn254::Field;
use usernode_circuits::prover::{
    SchnorrEnc, SpendInputEnc, TransferEnc, UtxoEnc, encode_spend_privates, init_default_circuits,
    prove,
};

#[allow(clippy::too_many_arguments)]
fn build_spend_inputs(
    sender: &Keypair,
    recipient: &Keypair,
    in_tokens: [Field; 4],
    in_amounts: [Field; 4],
    in_salt: Field,
    transfer_token: Field,
    transfer_amount: Field,
    fee_amount: Field,
    receiver_tokens: [Field; 4],
    receiver_amounts: [Field; 4],
    receiver_salt: Field,
    remainder_tokens: [Field; 4],
    remainder_amounts: [Field; 4],
    remainder_salt: Field,
) -> (SpendInputEnc, [u8; 32]) {
    let sender_pkx = sender.pk_x_bytes();
    let sender_pky = sender.pk_y_bytes();
    let recipient_pkx = recipient.pk_x_bytes();
    let sender_pkx_field = Field::from_bytes(sender_pkx);

    let receiver_utxo = Utxo {
        assets: [
            Asset {
                token: receiver_tokens[0],
                amount: receiver_amounts[0],
            },
            Asset {
                token: receiver_tokens[1],
                amount: receiver_amounts[1],
            },
            Asset {
                token: receiver_tokens[2],
                amount: receiver_amounts[2],
            },
            Asset {
                token: receiver_tokens[3],
                amount: receiver_amounts[3],
            },
        ],
        recipient_pk_x: Field::from_bytes(recipient_pkx),
        salt: receiver_salt,
    };
    let remainder_utxo = Utxo {
        assets: [
            Asset {
                token: remainder_tokens[0],
                amount: remainder_amounts[0],
            },
            Asset {
                token: remainder_tokens[1],
                amount: remainder_amounts[1],
            },
            Asset {
                token: remainder_tokens[2],
                amount: remainder_amounts[2],
            },
            Asset {
                token: remainder_tokens[3],
                amount: remainder_amounts[3],
            },
        ],
        recipient_pk_x: sender_pkx_field,
        salt: remainder_salt,
    };

    let out0 = utxo_commitment(&receiver_utxo);
    let out1 = utxo_commitment(&remainder_utxo);
    let msg32 = spend_digest(
        sender_pkx_field,
        transfer_token,
        transfer_amount,
        fee_amount,
        out0,
        out1,
    );

    let enc = SpendInputEnc {
        schnorr: SchnorrEnc {
            pk_x: sender_pkx,
            pk_y: sender_pky,
            sig64: [0u8; 64],
            msg32,
        },
        in0: UtxoEnc {
            assets_tokens: in_tokens,
            assets_amounts: in_amounts,
            recipient_pk_x: sender_pkx,
            salt: in_salt,
        },
        transfer: TransferEnc {
            token: transfer_token,
            amount: transfer_amount,
            fee: fee_amount,
        },
        receiver: UtxoEnc {
            assets_tokens: receiver_tokens,
            assets_amounts: receiver_amounts,
            recipient_pk_x: recipient_pkx,
            salt: receiver_salt,
        },
        remainder: UtxoEnc {
            assets_tokens: remainder_tokens,
            assets_amounts: remainder_amounts,
            recipient_pk_x: sender_pkx,
            salt: remainder_salt,
        },
    };

    (enc, msg32)
}

fn expect_prove_err(enc: &SpendInputEnc) {
    let privates = encode_spend_privates(enc);
    let result = prove("utxo_spend", &privates);
    assert!(result.is_err(), "expected proving failure");
}

#[test]
fn bad_signature_rejected() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([1u8; 32]);
    let attacker = Keypair::from_seed([2u8; 32]);
    let recipient = Keypair::from_seed([3u8; 32]);

    let in_tokens = [Field::from(7), Field::zero(), Field::zero(), Field::zero()];
    let in_amounts = [
        Field::from(100),
        Field::zero(),
        Field::zero(),
        Field::zero(),
    ];
    let receiver_tokens = [Field::from(7), Field::zero(), Field::zero(), Field::zero()];
    let receiver_amounts = [Field::from(40), Field::zero(), Field::zero(), Field::zero()];
    let remainder_tokens = in_tokens;
    let remainder_amounts = [Field::from(58), Field::zero(), Field::zero(), Field::zero()];

    let (mut enc, msg32) = build_spend_inputs(
        &sender,
        &recipient,
        in_tokens,
        in_amounts,
        Field::from(1u128),
        Field::from(7),
        Field::from(40),
        Field::from(2),
        receiver_tokens,
        receiver_amounts,
        Field::from(11u128),
        remainder_tokens,
        remainder_amounts,
        Field::from(22u128),
    );

    enc.schnorr.sig64 = attacker.sign(msg32);
    expect_prove_err(&enc);
}

#[test]
fn bad_msg32_rejected() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([4u8; 32]);
    let recipient = Keypair::from_seed([5u8; 32]);

    let in_tokens = [Field::from(7), Field::zero(), Field::zero(), Field::zero()];
    let in_amounts = [
        Field::from(100),
        Field::zero(),
        Field::zero(),
        Field::zero(),
    ];
    let receiver_tokens = [Field::from(7), Field::zero(), Field::zero(), Field::zero()];
    let receiver_amounts = [Field::from(40), Field::zero(), Field::zero(), Field::zero()];
    let remainder_tokens = in_tokens;
    let remainder_amounts = [Field::from(58), Field::zero(), Field::zero(), Field::zero()];

    let (mut enc, mut msg32) = build_spend_inputs(
        &sender,
        &recipient,
        in_tokens,
        in_amounts,
        Field::from(2u128),
        Field::from(7),
        Field::from(40),
        Field::from(2),
        receiver_tokens,
        receiver_amounts,
        Field::from(33u128),
        remainder_tokens,
        remainder_amounts,
        Field::from(44u128),
    );

    msg32[0] ^= 0x55;
    enc.schnorr.msg32 = msg32;
    enc.schnorr.sig64 = sender.sign(msg32);
    expect_prove_err(&enc);
}

#[test]
fn transfer_token_not_present_rejected() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([6u8; 32]);
    let recipient = Keypair::from_seed([7u8; 32]);

    let in_tokens = [
        Field::from(1),
        Field::from(2),
        Field::from(3),
        Field::from(4),
    ];
    let in_amounts = [
        Field::from(10),
        Field::from(20),
        Field::from(30),
        Field::from(40),
    ];
    let transfer_token = Field::from(99);
    let receiver_tokens = [transfer_token, Field::zero(), Field::zero(), Field::zero()];
    let receiver_amounts = [Field::from(5), Field::zero(), Field::zero(), Field::zero()];
    let remainder_tokens = in_tokens;
    let remainder_amounts = [
        Field::from(5),
        Field::from(20),
        Field::from(30),
        Field::from(40),
    ];

    let (mut enc, msg32) = build_spend_inputs(
        &sender,
        &recipient,
        in_tokens,
        in_amounts,
        Field::from(3u128),
        transfer_token,
        Field::from(5),
        Field::zero(),
        receiver_tokens,
        receiver_amounts,
        Field::from(10u128),
        remainder_tokens,
        remainder_amounts,
        Field::from(20u128),
    );

    enc.schnorr.sig64 = sender.sign(msg32);
    expect_prove_err(&enc);
}

#[test]
fn insufficient_fee_slot0_rejected() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([8u8; 32]);
    let recipient = Keypair::from_seed([9u8; 32]);

    let in_tokens = [Field::from(7), Field::zero(), Field::zero(), Field::zero()];
    let in_amounts = [Field::from(10), Field::zero(), Field::zero(), Field::zero()];
    let receiver_tokens = [Field::from(7), Field::zero(), Field::zero(), Field::zero()];
    let receiver_amounts = [Field::from(9), Field::zero(), Field::zero(), Field::zero()];
    let remainder_tokens = in_tokens;
    let remainder_amounts = [Field::zero(), Field::zero(), Field::zero(), Field::zero()];

    let (mut enc, msg32) = build_spend_inputs(
        &sender,
        &recipient,
        in_tokens,
        in_amounts,
        Field::from(5u128),
        Field::from(7),
        Field::from(9),
        Field::from(2),
        receiver_tokens,
        receiver_amounts,
        Field::from(77u128),
        remainder_tokens,
        remainder_amounts,
        Field::from(88u128),
    );

    enc.schnorr.sig64 = sender.sign(msg32);
    expect_prove_err(&enc);
}
