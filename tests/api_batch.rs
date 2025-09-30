//! Tests that exercise the batch planning helpers without the wider node.
//!
//! We build a tiny set of dummy leaves, run them through `plan_block`, and
//! compare the derived manifest hash/root with the expected Poseidon2 results.

use usernode_circuits::batch::{BindingLeaf, canonical_root_even, plan_block};
use usernode_circuits::bn254::Field;
use usernode_circuits::poseidon2::{hash_fields, hash_manifest};

#[test]
fn plan_block_drops_tail_and_hashes() {
    let base = Field::from(42u128);
    let leaves: Vec<BindingLeaf> = (0..3)
        .map(|i| BindingLeaf {
            leaf_id: vec![i],
            leaf_hash: hash_fields(&[base + Field::from(i as u128)]),
        })
        .collect();

    // Plan the block and confirm the last leaf is deferred (odd length).
    let block = plan_block(7, Field::from(100u128), leaves.clone());
    assert_eq!(block.block_id, 7);
    assert_eq!(block.leaves.len(), 2);
    assert!(block.deferred.is_some());

    let expected_hashes: Vec<Field> = leaves.iter().take(2).map(|l| l.leaf_hash).collect();
    assert_eq!(
        block.manifest_hash(),
        hash_manifest(7, Field::from(100u128), &expected_hashes),
    );

    let root = canonical_root_even(&expected_hashes).expect("even length root");
    assert_eq!(block.canonical_root_even().expect("root"), root);
}
