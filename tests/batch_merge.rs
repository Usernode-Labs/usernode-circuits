mod common;

use common::{
    Asset, Keypair, Utxo, fetch_public_inputs, field_from_bytes, field_to_bytes, proof_hash,
    spend_digest, utxo_commitment, vk_hash,
};

use usernode_circuits::bn254::Field;
use usernode_circuits::poseidon2::h2;
use usernode_circuits::prover::{
    SchnorrEnc, SpendInputEnc, TransferEnc, UtxoEnc, encode_spend_privates, get_circuit,
    init_default_circuits, merge_batch_h2, prove, verify,
};

#[test]
// Indexing is safe because the Barretenberg public input vector has a known
// layout; the indices match the original node assertions.
#[allow(clippy::indexing_slicing)]
fn batch_merge_binding_block_matches_expected() {
    init_default_circuits().expect("init embedded circuits");

    let sender = Keypair::from_seed([7u8; 32]);
    let recipient = Keypair::from_seed([9u8; 32]);
    let sender_pkx_bytes = sender.pk_x_bytes();
    let sender_pky_bytes = sender.pk_y_bytes();
    let recipient_pkx_bytes = recipient.pk_x_bytes();
    let sender_pkx_field = Field::from_bytes(sender_pkx_bytes);
    let recipient_pkx_field = Field::from_bytes(recipient_pkx_bytes);

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

    let remainder_tokens = in_tokens;
    let remainder_amounts = [
        Field::from(58u128),
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ];
    let remainder_salt = Field::from(2222u128);

    let prove_spend = |receiver_salt: Field| -> Vec<u8> {
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
            recipient_pk_x: recipient_pkx_field,
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

        let enc = SpendInputEnc {
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
        let privs = encode_spend_privates(&enc);
        prove("utxo_spend", &privs).expect("prove spend")
    };

    let proof_a = prove_spend(Field::from(1111u128));
    let proof_b = prove_spend(Field::from(2223u128));

    let circuit = get_circuit("utxo_spend").expect("circuit cache");
    let vk_a = circuit.vk.clone();
    let vk_b = circuit.vk.clone();

    let pis_a = fetch_public_inputs(&proof_a, &vk_a);
    let pis_b = fetch_public_inputs(&proof_b, &vk_b);
    assert_eq!(
        pis_a.len(),
        32,
        "expected single public input for spend leaf"
    );
    assert_eq!(
        pis_b.len(),
        32,
        "expected single public input for spend leaf"
    );

    let left = field_from_bytes(&pis_a[0..32]);
    let right = field_from_bytes(&pis_b[0..32]);
    let parent_expect = h2(left, right);

    let pl_hash = proof_hash(&proof_a, 60);
    let pr_hash = proof_hash(&proof_b, 60);
    let vkl_bytes = vk_hash(&vk_a);
    let vkr_bytes = vk_hash(&vk_b);

    let pl = field_from_bytes(&pl_hash);
    let pr = field_from_bytes(&pr_hash);
    let vkl = field_from_bytes(&vkl_bytes);
    let vkr = field_from_bytes(&vkr_bytes);

    let (merged_proof, merged_vk) =
        merge_batch_h2(&proof_a, &vk_a, &proof_b, &vk_b).expect("batch merge");

    let pis_m = fetch_public_inputs(&merged_proof, &merged_vk);
    assert_eq!(pis_m.len(), 7 * 32, "merged proof exposes binding block");

    let read_field = |idx_from_end: usize| -> Field {
        let words = pis_m.len() / 32;
        let field_idx = words - idx_from_end;
        let start = field_idx * 32;
        field_from_bytes(&pis_m[start..start + 32])
    };

    let right_pub = read_field(1);
    let left_pub = read_field(2);
    let vkr_pub = read_field(3);
    let pr_pub = read_field(4);
    let vkl_pub = read_field(5);
    let pl_pub = read_field(6);
    let parent_pub = read_field(7);

    assert_eq!(
        field_to_bytes(parent_pub),
        field_to_bytes(parent_expect),
        "parent"
    );
    assert_eq!(field_to_bytes(pl_pub), field_to_bytes(pl), "pl hash");
    assert_eq!(field_to_bytes(vkl_pub), field_to_bytes(vkl), "vkl hash");
    assert_eq!(field_to_bytes(pr_pub), field_to_bytes(pr), "pr hash");
    assert_eq!(field_to_bytes(vkr_pub), field_to_bytes(vkr), "vkr hash");
    assert_eq!(field_to_bytes(left_pub), field_to_bytes(left), "left");
    assert_eq!(field_to_bytes(right_pub), field_to_bytes(right), "right");

    assert!(verify("utxo_spend", &proof_a).expect("verify proof A"));
    assert!(verify("utxo_spend", &proof_b).expect("verify proof B"));
    let ok =
        aztec_barretenberg_rs::verify_mega_honk(&merged_proof, &merged_vk).expect("verify merged");
    assert!(ok, "merged proof must verify");
}
