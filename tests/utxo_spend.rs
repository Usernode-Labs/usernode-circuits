mod common;

use common::{Asset, Keypair, Utxo, spend_digest, utxo_commitment};

use usernode_circuits::bn254::Field;
use usernode_circuits::prover::{
    SchnorrEnc, SpendInputEnc, TransferEnc, UtxoEnc, encode_spend_privates, get_circuit,
    init_default_circuits, prove, verify,
};

#[test]
fn prove_and_verify_utxo_spend() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([7u8; 32]);
    let recipient = Keypair::from_seed([9u8; 32]);
    let sender_pkx_bytes = sender.pk_x_bytes();
    let sender_pky_bytes = sender.pk_y_bytes();
    let recipient_pkx_bytes = recipient.pk_x_bytes();
    let sender_pkx_field = Field::from_bytes(sender_pkx_bytes);

    let in_tokens = [
        Field::from(7u128),
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let in_amounts = [
        Field::from(100u128),
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let in_salt = Field::from(3333u128);

    let transfer_token = Field::from(7u128);
    let transfer_amount = Field::from(40u128);
    let fee_amount = Field::from(2u128);

    let receiver_tokens = [
        transfer_token,
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let receiver_amounts = [
        transfer_amount,
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let receiver_salt = Field::from(1111u128);

    let remainder_tokens = in_tokens;
    let remainder_amounts = [
        Field::from(58u128),
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let remainder_salt = Field::from(2222u128);

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
        recipient_pk_x: Field::from_bytes(recipient_pkx_bytes),
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
    let signature = sender.sign(msg32);
    assert!(
        sender.verify(msg32, signature),
        "schnorr signature must verify"
    );

    let spend_enc = SpendInputEnc {
        schnorr: SchnorrEnc {
            pk_x: sender_pkx_bytes,
            pk_y: sender_pky_bytes,
            sig64: signature,
            msg32,
        },
        in0: UtxoEnc {
            assets_tokens: in_tokens,
            assets_amounts: in_amounts,
            recipient_pk_x: sender_pkx_bytes,
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
            recipient_pk_x: recipient_pkx_bytes,
            salt: receiver_salt,
        },
        remainder: UtxoEnc {
            assets_tokens: remainder_tokens,
            assets_amounts: remainder_amounts,
            recipient_pk_x: sender_pkx_bytes,
            salt: remainder_salt,
        },
    };

    let privates = encode_spend_privates(&spend_enc);
    let proof = prove("utxo_spend", &privates).expect("prove utxo_spend");
    assert!(verify("utxo_spend", &proof).expect("verify utxo_spend"));

    let circuit = get_circuit("utxo_spend").expect("circuit present");
    let pis = common::fetch_public_inputs(&proof, &circuit.vk);
    assert_eq!(pis.len(), 32, "expected single public input");
}
