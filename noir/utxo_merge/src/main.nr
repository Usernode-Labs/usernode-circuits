// utxo_merge: Transparent merge INS=2 -> OUTS=1
// - Computes one output commitment committing pk_x directly (no pk-hash preimage)
// - Enforces per-slot equality of tokens across inputs and sums their amounts
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

struct Schnorr { pk_x: Field, pk_y: Field, sig64: [u8; 64], msg32: [u8; 32] }
struct Utxo { assets_tokens: [u64; 4], assets_amounts: [u64; 4], recipient_pk_x: Field, salt: Field }
struct MergeInput { schnorr: Schnorr, in0: Utxo, in1: Utxo, out: Utxo }
fn main(input: MergeInput, public_inputs: pub [Field; 1]) {
    // Inputs must be different UTXOs (guard against double-feeding the same input)
    let in_commit0 = commit_note(input.in0.recipient_pk_x, input.in0.assets_tokens, input.in0.assets_amounts, input.in0.salt);
    let in_commit1 = commit_note(input.in1.recipient_pk_x, input.in1.assets_tokens, input.in1.assets_amounts, input.in1.salt);
    assert(in_commit0 != in_commit1);

    // Per-slot token equality across inputs and with output; output amounts = sum of inputs (no overflow)
    for i in 0..4 {
        let t0 = input.in0.assets_tokens[i];
        let t1 = input.in1.assets_tokens[i];
        let to = input.out.assets_tokens[i];
        assert(t0 == t1);
        assert(to == t0);
        let a0 = input.in0.assets_amounts[i];
        let a1 = input.in1.assets_amounts[i];
        let ao = input.out.assets_amounts[i];
        // Prevent overflow: ao must be >= a0 and ao - a0 = a1
        assert(ao >= a0);
        assert(ao - a0 == a1);
    }

    // Output commitment (to sender pk_x)
    let out_commit = commit_note(input.out.recipient_pk_x, input.out.assets_tokens, input.out.assets_amounts, input.out.salt);
    // Input commitments already computed above: in_commit0, in_commit1

    // Canonical digest (tagged): [2, sender_pk_x, out_commit, 0, 0, 0]
    let digest = poseidon2_hash_fields([
        2, input.in0.recipient_pk_x, out_commit, 0, 0, 0
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

    // Compute leaf hash (tag=12)
    let leaf_hash = poseidon2_hash_fields([ 12, in_commit0, in_commit1, out_commit ]);
    // Bind as explicit public input to be consumed by the aggregator
    assert(public_inputs[0] == leaf_hash);
}
