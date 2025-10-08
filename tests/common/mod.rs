#![allow(dead_code)]

use std::sync::{Mutex, OnceLock};

use aztec_barretenberg_rs::{
    grumpkin_derive_pubkey, mega_proof_fields_hash, mega_vk_hash, schnorr_blake2s_sign,
    schnorr_blake2s_verify_xy,
};

use usernode_circuits::bn254::Field;
use usernode_circuits::poseidon2::{hash_fields, hash10};
use usernode_circuits::prover::fetch_batch_public_inputs;

fn guard() -> &'static Mutex<()> {
    static TEST_GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_GUARD.get_or_init(|| Mutex::new(()))
}

pub fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    guard().lock().expect("test mutex poisoned")
}

#[derive(Clone, Copy, Debug)]
pub struct Asset {
    pub token: Field,
    pub amount: Field,
}

#[derive(Clone, Copy, Debug)]
pub struct Utxo {
    pub assets: [Asset; 4],
    pub recipient_pk_x: Field,
    pub salt: Field,
}

pub fn utxo_commitment(utxo: &Utxo) -> Field {
    hash10([
        utxo.recipient_pk_x,
        utxo.assets[0].token,
        utxo.assets[0].amount,
        utxo.assets[1].token,
        utxo.assets[1].amount,
        utxo.assets[2].token,
        utxo.assets[2].amount,
        utxo.assets[3].token,
        utxo.assets[3].amount,
        utxo.salt,
    ])
}

#[allow(dead_code)]
pub fn spend_digest(
    sender_pk_x: Field,
    transfer_token: Field,
    transfer_amount: Field,
    fee_amount: Field,
    out0: Field,
    out1: Field,
) -> [u8; 32] {
    let digest = hash_fields(&[
        Field::from(1u128),
        sender_pk_x,
        transfer_token,
        transfer_amount,
        fee_amount,
        out0,
        out1,
    ]);
    digest.to_bytes()
}

#[allow(dead_code)]
pub fn merge_digest(sender_pk_x: Field, out: Field) -> [u8; 32] {
    let digest = hash_fields(&[
        Field::from(2u128),
        sender_pk_x,
        out,
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ]);
    digest.to_bytes()
}

pub struct Keypair {
    sk: [u8; 32],
    pk_x: [u8; 32],
    pk_y: [u8; 32],
}

impl Keypair {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (pk_x, pk_y) = grumpkin_derive_pubkey(&seed).expect("derive pubkey");
        Self {
            sk: seed,
            pk_x,
            pk_y,
        }
    }

    pub fn sign(&self, msg32: [u8; 32]) -> [u8; 64] {
        schnorr_blake2s_sign(&msg32, &self.sk).expect("sign")
    }

    #[allow(dead_code)]
    pub fn verify(&self, msg32: [u8; 32], sig64: [u8; 64]) -> bool {
        schnorr_blake2s_verify_xy(&msg32, &sig64, &self.pk_x, &self.pk_y).unwrap_or(false)
    }

    pub fn pk_x_bytes(&self) -> [u8; 32] {
        self.pk_x
    }

    pub fn pk_y_bytes(&self) -> [u8; 32] {
        self.pk_y
    }
}

#[allow(dead_code)]
pub fn field_from_bytes(bytes: &[u8]) -> Field {
    let mut be = [0u8; 32];
    be.copy_from_slice(bytes);
    Field::from_bytes(be)
}

#[allow(dead_code)]
pub fn field_to_bytes(field: Field) -> [u8; 32] {
    field.to_bytes()
}

#[allow(dead_code)]
pub fn fetch_public_inputs(proof: &[u8], vk_id: [u8; 32]) -> Vec<[u8; 32]> {
    fetch_batch_public_inputs(proof, vk_id).expect("mega public inputs")
}

#[allow(dead_code)]
pub fn proof_hash(proof: &[u8], tag: u32) -> [u8; 32] {
    mega_proof_fields_hash(proof, tag).expect("mega proof hash")
}

#[allow(dead_code)]
pub fn vk_hash(vk: &[u8]) -> [u8; 32] {
    mega_vk_hash(vk).expect("mega vk hash")
}
