//! Helpers for turning proved transactions into binding blocks and manifests.
//!
//! These utilities mirror the batching logic in the original node code but are
//! self-contained so tests in this crate can exercise ordering and hashing.
//! The focus is on documenting how leaf hashes flow into the manifest hash and
//! the pairwise Poseidon2 folding used to derive batch roots.

use crate::bn254::Field;
use crate::poseidon2::{h2, hash_manifest, hash_merge_leaf, hash_spend_leaf};
use crate::types::{MergeTx, SpendTx};

/// Hash binding for a single transaction leaf (either spend or merge).
#[derive(Clone, Debug)]
pub struct BindingLeaf {
    /// Caller-chosen identifier (e.g. transaction hash) carried through the block.
    pub leaf_id: Vec<u8>,
    /// Poseidon2 leaf hash produced by the circuit.
    pub leaf_hash: Field,
}

impl BindingLeaf {
    /// Build a binding leaf from a spend proof using the canonical leaf hash.
    pub fn from_spend(leaf_id: Vec<u8>, tx: &SpendTx) -> Self {
        Self {
            leaf_id,
            leaf_hash: tx.leaf_hash(),
        }
    }

    /// Build a binding leaf from a merge proof using the canonical leaf hash.
    pub fn from_merge(leaf_id: Vec<u8>, tx: &MergeTx) -> Self {
        Self {
            leaf_id,
            leaf_hash: tx.leaf_hash(),
        }
    }
}

/// Fully bound block manifest along with the optional deferred tail (if odd).
#[derive(Clone, Debug)]
pub struct BindingBlock {
    /// Sequential identifier of the block (matches node semantics).
    pub block_id: u64,
    /// Ledger root that all inputs were validated against.
    pub acceptance_root: Field,
    /// Even-length set of leaves included in the block.
    pub leaves: Vec<BindingLeaf>,
    /// Optional leftover leaf when the input count is odd.
    pub deferred: Option<BindingLeaf>,
}

impl BindingBlock {
    /// Poseidon2 hash covering the ordered leaves, block id, and root.
    pub fn manifest_hash(&self) -> Field {
        let hashes: Vec<Field> = self.leaves.iter().map(|l| l.leaf_hash).collect();
        hash_manifest(self.block_id, self.acceptance_root, &hashes)
    }

    /// Canonical pairwise Poseidon2 root of the even-length leaf sequence.
    pub fn canonical_root_even(&self) -> Option<Field> {
        canonical_root_even(
            self.leaves
                .iter()
                .map(|l| l.leaf_hash)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }
}

/// Build a binding block from an already ordered list of leaves.
///
/// The function enforces the “pair completeness” policy from the node by
/// moving the last leaf to `deferred` when the input length is odd. The even
/// prefix is used to compute the manifest hash and batch root.
pub fn plan_block(
    block_id: u64,
    acceptance_root: Field,
    mut leaves: Vec<BindingLeaf>,
) -> BindingBlock {
    let deferred = if leaves.len() % 2 == 1 {
        leaves.pop()
    } else {
        None
    };
    BindingBlock {
        block_id,
        acceptance_root,
        leaves,
        deferred,
    }
}

#[derive(Clone, Debug)]
pub struct CandidateLeaf {
    /// Caller-chosen identifier for traceability.
    pub leaf_id: Vec<u8>,
    /// Declared leaf hash to be validated.
    pub leaf_hash: Field,
    /// Arrival timestamp used as the primary sorting key.
    pub arrival_time_ns: u64,
    /// Publisher identifier used as tie-breaker.
    pub publisher_id: [u8; 32],
}

/// Deterministically order candidates and build a pair-complete block.
///
/// Sorting uses `(arrival_time, leaf_hash, publisher_id)` so the outcome is
/// stable across runs. The resulting block mirrors `plan_block` after the
/// ordering step.
pub fn plan_block_from_candidates(
    block_id: u64,
    acceptance_root: Field,
    mut candidates: Vec<CandidateLeaf>,
) -> BindingBlock {
    candidates.sort_by(|a, b| {
        a.arrival_time_ns
            .cmp(&b.arrival_time_ns)
            .then_with(|| field_cmp(&a.leaf_hash, &b.leaf_hash))
            .then_with(|| a.publisher_id.cmp(&b.publisher_id))
    });
    let leaves: Vec<BindingLeaf> = candidates
        .into_iter()
        .map(|c| BindingLeaf {
            leaf_id: c.leaf_id,
            leaf_hash: c.leaf_hash,
        })
        .collect();
    plan_block(block_id, acceptance_root, leaves)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafRecord {
    Spend {
        in_commit: Field,
        out_commit0: Field,
        out_commit1: Field,
        transfer_token: Field,
        transfer_amount: Field,
        fee_amount: Field,
    },
    Merge {
        in_commit0: Field,
        in_commit1: Field,
        out_commit: Field,
    },
}

impl LeafRecord {
    pub fn recompute_leaf_hash(&self) -> Field {
        match self {
            LeafRecord::Spend {
                in_commit,
                out_commit0,
                out_commit1,
                transfer_token,
                transfer_amount,
                fee_amount,
            } => hash_spend_leaf(
                *in_commit,
                *out_commit0,
                *out_commit1,
                *transfer_token,
                *transfer_amount,
                *fee_amount,
            ),
            LeafRecord::Merge {
                in_commit0,
                in_commit1,
                out_commit,
            } => hash_merge_leaf(*in_commit0, *in_commit1, *out_commit),
        }
    }

    pub fn outputs(&self) -> Vec<Field> {
        match self {
            LeafRecord::Spend {
                out_commit0,
                out_commit1,
                ..
            } => vec![*out_commit0, *out_commit1],
            LeafRecord::Merge { out_commit, .. } => vec![*out_commit],
        }
    }

    pub fn inputs(&self) -> Vec<Field> {
        match self {
            LeafRecord::Spend { in_commit, .. } => vec![*in_commit],
            LeafRecord::Merge {
                in_commit0,
                in_commit1,
                ..
            } => vec![*in_commit0, *in_commit1],
        }
    }
}

#[derive(Clone, Debug)]
pub struct CandidateWithRecord {
    /// Caller-chosen identifier for the candidate leaf.
    pub leaf_id: Vec<u8>,
    /// Arrival timestamp used for ordering.
    pub arrival_time_ns: u64,
    /// Publisher identifier used as a tie breaker.
    pub publisher_id: [u8; 32],
    /// Leaf record reconstructed from the submitted transaction.
    pub record: LeafRecord,
    /// Declared leaf hash (validated before inclusion).
    pub declared_leaf_hash: Field,
}

/// Validate candidate leaves (hash consistency, membership constraints) and plan a block.
pub fn validate_and_plan_block<FExists>(
    block_id: u64,
    acceptance_root: Field,
    mut candidates: Vec<CandidateWithRecord>,
    membership_exists: FExists,
) -> BindingBlock
where
    FExists: Fn(Field) -> bool,
{
    candidates.sort_by(|a, b| {
        a.arrival_time_ns
            .cmp(&b.arrival_time_ns)
            .then_with(|| field_cmp(&a.declared_leaf_hash, &b.declared_leaf_hash))
            .then_with(|| a.publisher_id.cmp(&b.publisher_id))
    });

    use std::collections::HashSet;
    let mut produced: HashSet<[u8; 32]> = HashSet::new();
    let mut consumed: HashSet<[u8; 32]> = HashSet::new();
    let mut leaves: Vec<BindingLeaf> = Vec::new();

    for cand in candidates.into_iter() {
        let recomputed = cand.record.recompute_leaf_hash();
        if recomputed != cand.declared_leaf_hash {
            continue;
        }

        if !inputs_ok(&cand.record, &membership_exists, &produced, &consumed) {
            continue;
        }

        for inp in cand.record.inputs() {
            consumed.insert(inp.to_bytes());
        }
        for out in cand.record.outputs() {
            produced.insert(out.to_bytes());
        }

        leaves.push(BindingLeaf {
            leaf_id: cand.leaf_id,
            leaf_hash: cand.declared_leaf_hash,
        });
    }

    plan_block(block_id, acceptance_root, leaves)
}

/// Check whether all inputs of a leaf record are available and unused.
fn inputs_ok<FExists>(
    record: &LeafRecord,
    membership_exists: &FExists,
    produced: &std::collections::HashSet<[u8; 32]>,
    consumed: &std::collections::HashSet<[u8; 32]>,
) -> bool
where
    FExists: Fn(Field) -> bool,
{
    for inp in record.inputs() {
        let key = inp.to_bytes();
        let prev = membership_exists(inp) || produced.contains(&key);
        if !prev || consumed.contains(&key) {
            return false;
        }
    }
    true
}

/// Compare two field elements using their big-endian byte encoding.
fn field_cmp(a: &Field, b: &Field) -> std::cmp::Ordering {
    a.to_bytes().cmp(&b.to_bytes())
}

/// Fold an even-length slice of leaf hashes using Poseidon2 H2 combiner.
pub fn canonical_root_even(hashes: &[Field]) -> Option<Field> {
    if hashes.is_empty() || hashes.len() % 2 == 1 {
        return None;
    }
    let mut level: Vec<Field> = hashes.to_vec();
    while level.len() > 1 {
        let mut next: Vec<Field> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            let [left, right] = match pair {
                [l, r] => [*l, *r],
                _ => return None,
            };
            next.push(h2(left, right));
        }
        level = next;
    }
    level.first().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_root_requires_even_length() {
        assert!(canonical_root_even(&[]).is_none());
        let xs = vec![Field::from(1u128)];
        assert!(canonical_root_even(&xs).is_none());
    }
}
