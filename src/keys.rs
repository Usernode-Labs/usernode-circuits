#![allow(clippy::module_name_repetitions)]

use aztec_barretenberg_rs::{
    grumpkin_derive_pubkey, schnorr_blake2s_sign, schnorr_blake2s_verify_xy,
};

/// Grumpkin Schnorr keypair backed by Barretenberg helpers.
///
/// The circuits expect callers to supply Schnorr signatures over a 32-byte
/// digest (`msg32`). `Keypair` matches the legacy usernode wallet interface so
/// higher-level components can reuse existing key material.
#[derive(Clone)]
pub struct Keypair {
    sk: [u8; 32],
    pk_x: [u8; 32],
    pk_y: [u8; 32],
}

impl Keypair {
    /// Deterministically derive a keypair from a 32-byte seed.
    pub fn from_seed(seed32: [u8; 32]) -> anyhow::Result<Self> {
        let (pk_x, pk_y) = grumpkin_derive_pubkey(&seed32)?;
        Ok(Self {
            sk: seed32,
            pk_x,
            pk_y,
        })
    }

    /// Return the x-only public key used by the circuits/commitments.
    pub fn public_key_xonly(&self) -> [u8; 32] {
        self.pk_x
    }

    /// Return both x and y coordinates for verification flows.
    pub fn public_key_xy(&self) -> ([u8; 32], [u8; 32]) {
        (self.pk_x, self.pk_y)
    }

    /// Sign a 32-byte prehash with Schnorr(Blake2s) over Grumpkin.
    pub fn sign_prehash(&self, msg32: [u8; 32]) -> [u8; 64] {
        schnorr_blake2s_sign(&msg32, &self.sk).expect("schnorr sign should succeed")
    }

    /// Verify a signature against the provided (x, y) public key pair.
    pub fn verify_with_xy(
        pk_x: [u8; 32],
        pk_y: [u8; 32],
        msg32: [u8; 32],
        sig64: [u8; 64],
    ) -> bool {
        schnorr_blake2s_verify_xy(&msg32, &sig64, &pk_x, &pk_y).unwrap_or(false)
    }
}
