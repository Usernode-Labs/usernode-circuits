mod common;

use common::serial_guard;
use usernode_circuits::artifacts;
use usernode_circuits::catalog::{self, CircuitEntry};
use usernode_circuits::prover;

#[test]
fn embedded_catalog_includes_metadata() {
    let _lock = serial_guard();
    catalog::clear();
    prover::init_default_circuits().expect("init embedded");

    let spend = prover::get_circuit("utxo_spend").expect("embedded spend circuit");
    assert!(!spend.vk.is_empty(), "embedded VK must be present");
    assert!(spend.vk_hash.is_some(), "embedded VK hash missing");
    assert_ne!(
        spend.key_id, [0u8; 32],
        "embedded key id should be non-zero"
    );

    catalog::clear();
}

#[test]
fn init_circuit_from_artifacts_populates_metadata() {
    let _lock = serial_guard();
    catalog::clear();

    let embed = artifacts::embedded()
        .iter()
        .find(|c| c.name == "utxo_spend")
        .expect("find embedded spend circuit");

    prover::init_circuit_from_artifacts("temp_spend", embed.acir, &[], embed.abi_json)
        .expect("register circuit");

    let entry = prover::get_circuit("temp_spend").expect("registered circuit");
    assert!(!entry.vk.is_empty(), "generated VK must be present");
    assert!(entry.vk_hash.is_some(), "generated VK hash missing");
    assert_ne!(
        entry.key_id, [0u8; 32],
        "generated key id should be non-zero"
    );

    catalog::clear();
}

#[test]
fn helper_accessors_surface_cached_metadata() {
    let _lock = serial_guard();
    catalog::clear();
    prover::init_default_circuits().expect("init embedded");

    let key_id = prover::get_key_id("utxo_spend").expect("key id");
    assert_ne!(key_id, [0u8; 32], "get_key_id should return non-zero id");

    let vk = prover::get_vk_bytes("utxo_spend").expect("vk bytes");
    assert!(!vk.is_empty(), "get_vk_bytes should return non-empty VK");

    let hash = prover::get_vk_hash("utxo_spend").expect("vk hash");
    assert_ne!(hash, [0u8; 32], "vk hash should not be zero");

    catalog::clear();
}

#[test]
fn get_vk_hash_backfills_missing_cache() {
    let _lock = serial_guard();
    catalog::clear();

    let embed = artifacts::embedded()
        .iter()
        .find(|c| c.name == "utxo_spend")
        .expect("find embedded spend circuit");

    prover::init_circuit_from_artifacts("temp_spend", embed.acir, embed.vk, embed.abi_json)
        .expect("register with embedded data");
    let entry = prover::get_circuit("temp_spend").expect("registered circuit");
    let cached_hash = entry.vk_hash.expect("expected initial vk hash");

    // Reinsert without the cached hash to exercise the helper.
    catalog::clear();
    catalog::insert(CircuitEntry {
        name: entry.name.clone(),
        acir: entry.acir.clone(),
        vk: entry.vk.clone(),
        abi: entry.abi.clone(),
        key_id: entry.key_id,
        vk_hash: None,
    });

    let recomputed = prover::get_vk_hash(entry.name.as_str()).expect("recomputed hash");
    assert_eq!(recomputed, cached_hash, "hash mismatch after recomputation");

    // Cache should now contain the hash again.
    let refreshed = prover::get_circuit(entry.name.as_str()).expect("cached entry");
    assert_eq!(refreshed.vk_hash, Some(cached_hash));

    catalog::clear();
}

#[test]
fn get_vk_bytes_regenerates_missing_vk() {
    let _lock = serial_guard();
    catalog::clear();

    let embed = artifacts::embedded()
        .iter()
        .find(|c| c.name == "utxo_spend")
        .expect("find embedded spend circuit");

    prover::init_circuit_from_artifacts("temp_spend", embed.acir, &[], embed.abi_json)
        .expect("register circuit");
    let entry = prover::get_circuit("temp_spend").expect("registered circuit");

    catalog::clear();
    catalog::insert(CircuitEntry {
        name: entry.name.clone(),
        acir: entry.acir.clone(),
        vk: Vec::new(),
        abi: entry.abi.clone(),
        key_id: entry.key_id,
        vk_hash: None,
    });

    let regenerated = prover::get_vk_bytes(entry.name.as_str()).expect("vk bytes");
    assert!(
        !regenerated.is_empty(),
        "helper should regenerate verifying key"
    );

    let refreshed = prover::get_circuit(entry.name.as_str()).expect("cached entry");
    assert!(
        !refreshed.vk.is_empty(),
        "vk should be cached after regeneration"
    );
    assert!(refreshed.vk_hash.is_some(), "vk hash should also be cached");

    catalog::clear();
}
