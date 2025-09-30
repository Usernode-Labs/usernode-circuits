// utxo_spend: Transparent spend INS=1 -> OUTS=2
// - Computes two output commitments committing pk_x directly (no pk-hash preimage)
// - Enforces transfer semantics for a single token/amount
// - Computes canonical digest with numeric tag and verifies Schnorr over it

use std::embedded_curve_ops::EmbeddedCurvePoint;
use dep::schnorr;

// Minimal Poseidon2 sponge over BN254 using Barretenberg's exposed permutation.
comptime global RATE: u32 = 3; // capacity = 1

fn poseidon2_hash_fields<let N: u32>(input: [Field; N]) -> Field {
    // Domain IV: (in_len << 64) + (out_len-1), out_len=1
    let two_pow_64 = 18446744073709551616;
    let iv: Field = (N as Field) * two_pow_64;
    let mut state: [Field; 4] = [0; 4];
    state[RATE] = iv;
    let mut cache: [Field; RATE] = [0; RATE];
    let mut cache_size: u32 = 0;
    for i in 0..N {
        if cache_size == RATE {
            for j in 0..RATE { state[j] += cache[j]; }
            state = std::hash::poseidon2_permutation(state, 4);
            for j in 0..RATE { cache[j] = 0; }
            cache[0] = input[i];
            cache_size = 1;
        } else {
            cache[cache_size] = input[i];
            cache_size += 1;
        }
    }
    for j in 0..RATE {
        if j < cache_size { state[j] += cache[j]; }
    }
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

fn commit_note(pk_x: Field, tokens: [u64; 4], amounts: [u64; 4], salt: Field) -> Field {
    // Poseidon2 over [pk_x, (t0,a0), ..., (t3,a3), salt]
    poseidon2_hash_fields([
        pk_x,
        tokens[0] as Field, amounts[0] as Field,
        tokens[1] as Field, amounts[1] as Field,
        tokens[2] as Field, amounts[2] as Field,
        tokens[3] as Field, amounts[3] as Field,
        salt,
    ])
}

// Structured inputs/outputs
struct Schnorr {
    pk_x: Field,
    pk_y: Field,
    sig64: [u8; 64],
    msg32: [u8; 32],
}

struct Utxo {
    assets_tokens: [u64; 4],
    assets_amounts: [u64; 4],
    recipient_pk_x: Field,
    salt: Field,
}

struct Transfer {
    token: u64,
    amount: u64,
    fee: u64,
}

struct SpendInput {
    schnorr: Schnorr,
    in0: Utxo,
    transfer: Transfer,
    receiver: Utxo,
    remainder: Utxo,
}

fn main(input: SpendInput, public_inputs: pub [Field; 1]) {
    // Enforce single-token transfer semantics
    let mut matches: Field = 0;
    let mut idx: u32 = 0;
    for i in 0..4 {
        let eq = if input.in0.assets_tokens[i] == input.transfer.token { 1 } else { 0 };
        matches += eq;
        if eq == 1 { idx = i as u32; }
    }
    assert(matches == 1);

    // Receiver output (unrolled slot 0, then loop 1..4)
    if idx == 0 {
        assert(input.receiver.assets_tokens[0] == input.transfer.token);
        assert(input.receiver.assets_amounts[0] == input.transfer.amount);
    } else {
        assert(input.receiver.assets_tokens[0] == 0);
        assert(input.receiver.assets_amounts[0] == 0);
    }
    for i in 1..4 {
        if i as u32 == idx {
            assert(input.receiver.assets_tokens[i] == input.transfer.token);
            assert(input.receiver.assets_amounts[i] == input.transfer.amount);
        } else {
            assert(input.receiver.assets_tokens[i] == 0);
            assert(input.receiver.assets_amounts[i] == 0);
        }
    }

    // Remainder output (unrolled slot 0, then loop 1..4)
    if idx == 0 {
        assert(input.remainder.assets_tokens[0] == input.transfer.token);
        assert(input.in0.assets_amounts[0] >= input.transfer.amount + input.transfer.fee);
        assert(input.remainder.assets_amounts[0] == input.in0.assets_amounts[0] - input.transfer.amount - input.transfer.fee);
    } else {
        assert(input.remainder.assets_tokens[0] == input.in0.assets_tokens[0]);
        assert(input.in0.assets_amounts[0] >= input.transfer.fee);
        assert(input.remainder.assets_amounts[0] == input.in0.assets_amounts[0] - input.transfer.fee);
    }
    for i in 1..4 {
        if i as u32 == idx {
            assert(input.remainder.assets_tokens[i] == input.transfer.token);
            assert(input.in0.assets_amounts[i] >= input.transfer.amount);
            assert(input.remainder.assets_amounts[i] == input.in0.assets_amounts[i] - input.transfer.amount);
        } else {
            assert(input.remainder.assets_tokens[i] == input.in0.assets_tokens[i]);
            assert(input.remainder.assets_amounts[i] == input.in0.assets_amounts[i]);
        }
    }

    // Output commitments (commit pk_x directly)
    let receiver_commit = commit_note(input.receiver.recipient_pk_x, input.receiver.assets_tokens, input.receiver.assets_amounts, input.receiver.salt);
    let remainder_commit = commit_note(input.in0.recipient_pk_x, input.remainder.assets_tokens, input.remainder.assets_amounts, input.remainder.salt);
    // Prevent accidental duplicate outputs in the same transaction
    assert(receiver_commit != remainder_commit);
    // Input commitment
    let in_commit = commit_note(input.in0.recipient_pk_x, input.in0.assets_tokens, input.in0.assets_amounts, input.in0.salt);

    // Canonical digest (tagged): [1, sender_pk_x, transfer_token, transfer_amount, out_commit0, out_commit1]
    let digest = poseidon2_hash_fields([
        1,
        input.in0.recipient_pk_x,
        input.transfer.token as Field,
        input.transfer.amount as Field,
        input.transfer.fee as Field,
        receiver_commit,
        remainder_commit,
    ]);

    // Bind msg32 bytes to the computed digest by reconstructing a Field from bytes (BE)
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 256 + (input.schnorr.msg32[i] as Field);
    }
    assert(acc == digest);

    // Verify signature over computed msg32
    let pubkey = EmbeddedCurvePoint { x: input.schnorr.pk_x, y: input.schnorr.pk_y, is_infinite: false };
    let ok = schnorr::verify_signature(pubkey, input.schnorr.sig64, input.schnorr.msg32);
    assert(ok);

    // Compute leaf hash (tag=11)
    let leaf_hash = poseidon2_hash_fields([
        11,
        in_commit,
        receiver_commit,
        remainder_commit,
        input.transfer.token as Field,
        input.transfer.amount as Field,
        input.transfer.fee as Field,
    ]);
    // Bind as explicit public input to be consumed by the aggregator
    assert(public_inputs[0] == leaf_hash);
}
