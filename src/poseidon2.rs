#![deny(unsafe_op_in_unsafe_fn)]

use crate::bn254::Field;

const LEAF_SPEND_TAG: u128 = 11;
const LEAF_MERGE_TAG: u128 = 12;
const BATCH_TAG: u128 = 20;
const MANIFEST_TAG: u128 = 40;

fn permute4(state: [Field; 4]) -> [Field; 4] {
    let mut buf = [0u8; 32 * 4];
    for (dst, fe) in buf.chunks_mut(32).zip(state.iter()) {
        dst.copy_from_slice(fe.as_ref());
    }
    let mut out_ptr: *mut u8 = core::ptr::null_mut();
    let mut out_len: usize = 0;
    let rc = unsafe {
        aztec_barretenberg_sys_rs::bb_poseidon2_permutation_bn254(
            buf.as_ptr(),
            4,
            &mut out_ptr,
            &mut out_len,
        )
    };
    assert_eq!(rc, 0, "poseidon2_permutation failed");
    assert_eq!(out_len, 128, "poseidon2_permutation returned wrong length");
    let out_slice = unsafe { core::slice::from_raw_parts(out_ptr, out_len) };
    let mut out = [Field::from(0u128); 4];
    for (slot, chunk) in out.iter_mut().zip(out_slice.chunks(32).take(4)) {
        let mut be32 = [0u8; 32];
        be32.copy_from_slice(chunk);
        *slot = Field::from_bytes(be32);
    }
    unsafe { aztec_barretenberg_sys_rs::bb_free(out_ptr) };
    out
}

#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn hash_fields(inputs: &[Field]) -> Field {
    const RATE: usize = 3;
    let two_pow_64 = Field::from((1u128) << 64);
    let iv = two_pow_64 * Field::from(inputs.len() as u128);
    let mut state = [Field::from(0u128); 4];
    state[RATE] = iv;
    let mut cache = [Field::from(0u128); RATE];
    let mut cache_size = 0usize;

    for &f in inputs {
        if cache_size == RATE {
            for (s, c) in state.iter_mut().take(RATE).zip(cache.iter()) {
                *s += *c;
            }
            state = permute4(state);
            cache = [Field::from(0u128); RATE];
            cache[0] = f;
            cache_size = 1;
        } else {
            cache[cache_size] = f;
            cache_size += 1;
        }
    }
    for (j, (s, c)) in state.iter_mut().take(RATE).zip(cache.iter()).enumerate() {
        if j < cache_size {
            *s += *c;
        }
    }
    state = permute4(state);
    state[0]
}

pub fn hash6(xs: [Field; 6]) -> Field {
    hash_fields(&xs)
}

pub fn hash10(xs: [Field; 10]) -> Field {
    hash_fields(&xs)
}

pub fn h2(left: Field, right: Field) -> Field {
    hash_fields(&[Field::from(BATCH_TAG), left, right])
}

pub fn hash_spend_leaf(
    in_commit: Field,
    out_commit0: Field,
    out_commit1: Field,
    transfer_token: Field,
    transfer_amount: Field,
    fee_amount: Field,
) -> Field {
    hash_fields(&[
        Field::from(LEAF_SPEND_TAG),
        in_commit,
        out_commit0,
        out_commit1,
        transfer_token,
        transfer_amount,
        fee_amount,
    ])
}

pub fn hash_merge_leaf(in_commit0: Field, in_commit1: Field, out_commit: Field) -> Field {
    hash_fields(&[
        Field::from(LEAF_MERGE_TAG),
        in_commit0,
        in_commit1,
        out_commit,
    ])
}

pub fn hash_manifest(
    block_id: u64,
    acceptance_root: Field,
    leaf_hashes_in_order: &[Field],
) -> Field {
    let leaves_digest = hash_fields(leaf_hashes_in_order);
    hash_fields(&[
        Field::from(MANIFEST_TAG),
        Field::from(block_id as u128),
        acceptance_root,
        Field::from(leaf_hashes_in_order.len() as u128),
        leaves_digest,
    ])
}
