//! High-level transaction helpers that sit on top of the Noir circuits.
//!
//! The goal of this module is to provide a small, ergonomic API for building
//! spend and merge transactions without exposing Noir ABI details. Callers pass
//! strongly typed requests (`SpendRequest`, `MergeRequest`) and receive
//! `SpendTx`/`MergeTx` values containing proofs, Poseidon2 digests, and output
//! commitments. Internally we translate the friendly types into the exact Noir
//! layout by filling a `HashMap<String, Vec<FE>>` where each key matches a
//! field inside the circuit structs (for example `input.schnorr.pk_x`).
//! Barretenberg then turns those inputs into witness values and produces the
//! proof. This keeps the knowledge of how public/private inputs map to circuit
//! witnesses in one place.

use std::collections::HashMap;

use acir::AcirField;
use acir_field::FieldElement as FE;
use rand::RngCore;

use crate::bn254::Field;
use crate::keys::Keypair;
use crate::poseidon2::hash_fields;
use crate::prover;
use crate::types::{Asset, MergeInput, MergeTx, SpendInput, TransactionOutput, Utxo};

const SPEND_CIRCUIT: &str = "utxo_spend";
const MERGE_CIRCUIT: &str = "utxo_merge";

type EnsureUniqueFn = dyn Fn(&[Field]) -> anyhow::Result<bool>;

/// Lazily register the named circuit in the embedded catalog.
///
/// The first caller triggers `init_default_circuits`, which loads the ACIR,
/// verification keys, and ABI JSON that ship with this crate. Subsequent calls
/// become cheap existence checks, ensuring that proof generation always has
/// the necessary artefacts ready.
fn ensure_circuit_loaded(name: &str) -> anyhow::Result<()> {
    if prover::get_circuit(name).is_some() {
        return Ok(());
    }
    prover::init_default_circuits()?;
    anyhow::ensure!(
        prover::get_circuit(name).is_some(),
        "circuit {name} is not registered"
    );
    Ok(())
}

/// Sample a cryptographically random field element for use as a salt.
///
/// Salts appear in UTXO commitments and transaction digests. Using
/// `OsRng` keeps the behaviour identical to the historic node implementation.
fn random_salt_field() -> Field {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Field::from_bytes(bytes)
}

/// Helper to inject 32-byte big-endian field encodings into ACIR field values.
fn fe_from_field_bytes(be32: &[u8; 32]) -> FE {
    FE::from_be_bytes_reduce(be32)
}

/// Convert a BN254 `Field` into the ACIR representation used by Noir.
fn fe_from_field(f: &Field) -> FE {
    fe_from_field_bytes(f.as_ref())
}

/// Lift a raw byte into the ACIR field.
fn fe_from_u8(v: u8) -> FE {
    FE::from(v as u128)
}

/// High-level input for a spend proof.
pub struct SpendRequest<'a> {
    /// Schnorr keypair that authorises the transaction.
    pub signer: &'a Keypair,
    /// Receiver public key x-coordinate (the Noir circuit uses x-only keys).
    pub recipient_pk_x: [u8; 32],
    /// Input payload for the consumed UTXO.
    pub input: SpendInput,
    /// Token to transfer to the receiver.
    pub transfer_token: Field,
    /// Amount to transfer to the receiver.
    pub transfer_amount: Field,
    /// Amount to pay as fee (deducted from slot 0 / remainder output).
    pub fee_amount: Field,
    /// Optional uniqueness check for the output commitments.
    pub ensure_unique: Option<&'a EnsureUniqueFn>,
    /// Run `verify` after proving; useful during tests and debugging.
    pub verify_proof: bool,
}

/// High-level input for a merge proof.
pub struct MergeRequest<'a> {
    /// Schnorr keypair that authorises the transaction.
    pub signer: &'a Keypair,
    /// Input payloads for the two consumed UTXOs.
    pub inputs: [MergeInput; 2],
    /// Token identifiers for the merged output.
    pub out_tokens: [Field; 4],
    /// Amounts for the merged output.
    pub out_amounts: [Field; 4],
    /// Optional salt override (random when `None`).
    pub out_salt: Option<Field>,
    /// Optional uniqueness check for the output commitment.
    pub ensure_unique: Option<&'a EnsureUniqueFn>,
    /// Run `verify` after proving; useful during tests and debugging.
    pub verify_proof: bool,
}

/// Build the Noir ABI for a spend, generate the proof, and return a rich result.
///
/// Steps:
/// 1. Derive the receiver and remainder UTXOs plus their Poseidon2 commitments.
/// 2. Populate the Noir ABI map (`input.*` keys) so
///    `prove_with_all_inputs` can translate the values into witness indices.
/// 3. Sign the canonical digest, inject the signature into the ABI, and call
///    Barretenberg to obtain the proof bytes.
/// 4. Reconstruct the typed outputs and bundle everything into `SpendTx`.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub fn prove_spend(req: SpendRequest<'_>) -> anyhow::Result<crate::types::SpendTx> {
    ensure_circuit_loaded(SPEND_CIRCUIT)?;
    let SpendRequest {
        signer,
        recipient_pk_x,
        input,
        transfer_token,
        transfer_amount,
        fee_amount,
        ensure_unique,
        verify_proof,
    } = req;

    let (sender_pkx, sender_pky) = signer.public_key_xy();

    anyhow::ensure!(
        sender_pkx == input.signer.pk_x_bytes() && sender_pky == input.signer.pk_y_bytes(),
        "signer keypair does not match spend input public key",
    );
    anyhow::ensure!(
        input.utxo.recipient_pk_x == input.signer.pk_x_field(),
        "spend input utxo recipient key does not match signer key",
    );

    // Precompute input token/amount arrays
    let in_tokens = [
        input.utxo.assets[0].token,
        input.utxo.assets[1].token,
        input.utxo.assets[2].token,
        input.utxo.assets[3].token,
    ];
    let in_amounts = [
        input.utxo.assets[0].amount,
        input.utxo.assets[1].amount,
        input.utxo.assets[2].amount,
        input.utxo.assets[3].amount,
    ];
    let in_salt = input.utxo.salt;

    // Locate slot for the transfer token
    let mut transfer_slot: Option<usize> = None;
    for (idx, token) in in_tokens.iter().enumerate() {
        if *token == transfer_token {
            if transfer_slot.is_some() {
                anyhow::bail!("duplicate transfer token slots detected");
            }
            transfer_slot = Some(idx);
        }
    }
    let transfer_slot =
        transfer_slot.ok_or_else(|| anyhow::anyhow!("transfer token not present in input UTXO"))?;

    let mut receiver_tokens = [Field::from(0u128); 4];
    let mut receiver_amounts = [Field::from(0u128); 4];
    receiver_tokens[transfer_slot] = transfer_token;
    receiver_amounts[transfer_slot] = transfer_amount;

    let remainder_tokens = in_tokens;
    let mut remainder_amounts = in_amounts;
    if transfer_slot == 0 {
        anyhow::ensure!(
            in_amounts[0] >= transfer_amount + fee_amount,
            "insufficient funds for transfer and fee"
        );
        remainder_amounts[0] = in_amounts[0] - transfer_amount - fee_amount;
    } else {
        anyhow::ensure!(
            in_amounts[transfer_slot] >= transfer_amount,
            "insufficient funds for transfer"
        );
        remainder_amounts[transfer_slot] = in_amounts[transfer_slot] - transfer_amount;
        anyhow::ensure!(
            in_amounts[0] >= fee_amount,
            "insufficient funds to pay fee from slot 0"
        );
        remainder_amounts[0] = in_amounts[0] - fee_amount;
    }

    let mut receiver_salt = random_salt_field();
    let mut remainder_salt = random_salt_field();

    let prepared = loop {
        let pack = pack_spend_inputs(SpendInputs {
            sender_pkx_be: input.signer.pk_x_bytes(),
            sender_pky_be: input.signer.pk_y_bytes(),
            recipient_pkx_be: recipient_pk_x,
            in_tokens,
            in_amounts,
            in_salt,
            transfer_token,
            transfer_amount,
            fee_amount,
            receiver_tokens,
            receiver_amounts,
            receiver_salt,
            remainder_tokens,
            remainder_amounts,
            remainder_salt,
        });

        if let Some(check_fn) = ensure_unique
            && check_fn(&[pack.receiver_commit, pack.remainder_commit])?
        {
            receiver_salt = random_salt_field();
            remainder_salt = random_salt_field();
            continue;
        }
        break pack;
    };

    let signature = signer.sign_prehash(prepared.msg32);
    let mut private_inputs = prepared.abi_inputs;
    private_inputs.insert(
        "input.schnorr.sig64".to_string(),
        signature.iter().map(|b| fe_from_u8(*b)).collect(),
    );

    let proof = prover::prove_with_all_inputs(SPEND_CIRCUIT, &private_inputs)?;
    if verify_proof {
        anyhow::ensure!(
            prover::verify(SPEND_CIRCUIT, &proof)?,
            "generated spend proof failed verification"
        );
    }

    let receiver_utxo = Utxo {
        assets: array_init::array_init(|idx| Asset {
            token: receiver_tokens[idx],
            amount: receiver_amounts[idx],
        }),
        recipient_pk_x: Field::from_bytes(recipient_pk_x),
        salt: receiver_salt,
    };
    let remainder_utxo = Utxo {
        assets: array_init::array_init(|idx| Asset {
            token: remainder_tokens[idx],
            amount: remainder_amounts[idx],
        }),
        recipient_pk_x: Field::from_bytes(sender_pkx),
        salt: remainder_salt,
    };

    Ok(crate::types::SpendTx {
        input,
        outputs: TransactionOutput::Spend {
            receiver: receiver_utxo,
            remainder: remainder_utxo,
        },
        expected_out_commits: [prepared.receiver_commit, prepared.remainder_commit],
        proof,
        transfer_token,
        transfer_amount,
        fee_amount,
        signature,
        msg32: prepared.msg32,
        digest: prepared.digest,
    })
}

/// Build the Noir ABI for a merge, generate the proof, and return a rich result.
///
/// The flow mirrors `prove_spend`, but with two inputs and a single output. We
/// derive the output commitment, fill `input.*` entries for both inputs and the
/// result, and return a `MergeTx` once Barretenberg produces the proof.
#[allow(clippy::indexing_slicing)]
pub fn prove_merge(req: MergeRequest<'_>) -> anyhow::Result<MergeTx> {
    ensure_circuit_loaded(MERGE_CIRCUIT)?;
    let MergeRequest {
        signer,
        inputs,
        out_tokens,
        out_amounts,
        out_salt,
        ensure_unique,
        verify_proof,
    } = req;

    let (sender_pkx, sender_pky) = signer.public_key_xy();

    anyhow::ensure!(
        sender_pkx == inputs[0].signer.pk_x_bytes() && sender_pky == inputs[0].signer.pk_y_bytes(),
        "signer keypair does not match merge input[0] public key",
    );
    anyhow::ensure!(
        sender_pkx == inputs[1].signer.pk_x_bytes() && sender_pky == inputs[1].signer.pk_y_bytes(),
        "signer keypair does not match merge input[1] public key",
    );
    anyhow::ensure!(
        inputs[0].signer.pk_x_bytes() == inputs[1].signer.pk_x_bytes()
            && inputs[0].signer.pk_y_bytes() == inputs[1].signer.pk_y_bytes(),
        "merge inputs must share the same signer",
    );
    anyhow::ensure!(
        inputs[0].utxo.recipient_pk_x == inputs[0].signer.pk_x_field()
            && inputs[1].utxo.recipient_pk_x == inputs[1].signer.pk_x_field(),
        "merge input utxo recipient key does not match signer key",
    );

    let mut output_salt = out_salt.unwrap_or_else(random_salt_field);

    let prepared = loop {
        let pack = pack_merge_inputs(MergeInputs {
            sender_pkx_be: inputs[0].signer.pk_x_bytes(),
            sender_pky_be: inputs[0].signer.pk_y_bytes(),
            in0_tokens: array_init::array_init(|idx| inputs[0].utxo.assets[idx].token),
            in0_amounts: array_init::array_init(|idx| inputs[0].utxo.assets[idx].amount),
            in0_salt: inputs[0].utxo.salt,
            in1_tokens: array_init::array_init(|idx| inputs[1].utxo.assets[idx].token),
            in1_amounts: array_init::array_init(|idx| inputs[1].utxo.assets[idx].amount),
            in1_salt: inputs[1].utxo.salt,
            out_tokens,
            out_amounts,
            out_salt: output_salt,
        });
        if let Some(check_fn) = ensure_unique
            && check_fn(&[pack.out_commit])?
        {
            output_salt = random_salt_field();
            continue;
        }
        break pack;
    };

    let signature = signer.sign_prehash(prepared.msg32);
    let mut private_inputs = prepared.abi_inputs;
    private_inputs.insert(
        "input.schnorr.sig64".to_string(),
        signature.iter().map(|b| fe_from_u8(*b)).collect(),
    );

    let proof = prover::prove_with_all_inputs(MERGE_CIRCUIT, &private_inputs)?;
    if verify_proof {
        anyhow::ensure!(
            prover::verify(MERGE_CIRCUIT, &proof)?,
            "generated merge proof failed verification"
        );
    }

    let merged_utxo = Utxo {
        assets: array_init::array_init(|idx| Asset {
            token: out_tokens[idx],
            amount: out_amounts[idx],
        }),
        recipient_pk_x: Field::from_bytes(sender_pkx),
        salt: output_salt,
    };

    Ok(MergeTx {
        inputs,
        outputs: TransactionOutput::Merge { utxo: merged_utxo },
        expected_out_commit: prepared.out_commit,
        proof,
        signature,
        msg32: prepared.msg32,
        digest: prepared.digest,
    })
}

/// Internal representation of the Noir `SpendInput` struct.
struct SpendInputs {
    sender_pkx_be: [u8; 32],
    sender_pky_be: [u8; 32],
    recipient_pkx_be: [u8; 32],
    in_tokens: [Field; 4],
    in_amounts: [Field; 4],
    in_salt: Field,
    transfer_token: Field,
    transfer_amount: Field,
    fee_amount: Field,
    receiver_tokens: [Field; 4],
    receiver_amounts: [Field; 4],
    receiver_salt: Field,
    remainder_tokens: [Field; 4],
    remainder_amounts: [Field; 4],
    remainder_salt: Field,
}

/// Packed spend inputs alongside the derived commitments/digest.
struct SpendPrepared {
    /// Noir-style ABI map (`input.*` keys) ready for `prove_with_all_inputs`.
    abi_inputs: HashMap<String, Vec<FE>>,
    /// Expected receiver commitment (circuits expose this publicly).
    receiver_commit: Field,
    /// Expected remainder commitment (circuits expose this publicly).
    remainder_commit: Field,
    /// Full Poseidon2 digest representing the transaction pre-hash.
    digest: Field,
    /// Digest truncated to 32 bytes (what Schnorr signs).
    msg32: [u8; 32],
}

/// Serialise the spend inputs into Noir ABI order and compute commitments.
///
/// The returned `HashMap<String, Vec<FE>>` mirrors the Noir struct paths (for
/// example `input.schnorr.pk_x`). `prove_with_all_inputs` later flattens this
/// map into the witness vector that Barretenberg consumes. Keeping the string
/// keys here documents the ABI contract in one place.
#[allow(clippy::indexing_slicing)]
fn pack_spend_inputs(inputs: SpendInputs) -> SpendPrepared {
    let receiver = Utxo {
        assets: array_init::array_init(|idx| Asset {
            token: inputs.receiver_tokens[idx],
            amount: inputs.receiver_amounts[idx],
        }),
        recipient_pk_x: Field::from_bytes(inputs.recipient_pkx_be),
        salt: inputs.receiver_salt,
    };
    let remainder = Utxo {
        assets: array_init::array_init(|idx| Asset {
            token: inputs.remainder_tokens[idx],
            amount: inputs.remainder_amounts[idx],
        }),
        recipient_pk_x: Field::from_bytes(inputs.sender_pkx_be),
        salt: inputs.remainder_salt,
    };
    let receiver_commit = receiver.commitment();
    let remainder_commit = remainder.commitment();

    let digest = hash_fields(&[
        Field::from(1u128),
        Field::from_bytes(inputs.sender_pkx_be),
        inputs.transfer_token,
        inputs.transfer_amount,
        inputs.fee_amount,
        receiver_commit,
        remainder_commit,
    ]);
    let msg32 = digest.to_bytes();

    let mut map: HashMap<String, Vec<FE>> = HashMap::new();
    map.insert(
        "input.schnorr.pk_x".into(),
        vec![fe_from_field_bytes(&inputs.sender_pkx_be)],
    );
    map.insert(
        "input.schnorr.pk_y".into(),
        vec![fe_from_field_bytes(&inputs.sender_pky_be)],
    );
    map.insert(
        "input.schnorr.msg32".into(),
        msg32.iter().map(|b| fe_from_u8(*b)).collect(),
    );
    map.insert(
        "input.in0.assets_tokens".into(),
        inputs.in_tokens.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.in0.assets_amounts".into(),
        inputs.in_amounts.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.in0.recipient_pk_x".into(),
        vec![fe_from_field_bytes(&inputs.sender_pkx_be)],
    );
    map.insert(
        "input.in0.salt".into(),
        vec![fe_from_field(&inputs.in_salt)],
    );
    map.insert(
        "input.transfer.token".into(),
        vec![fe_from_field(&inputs.transfer_token)],
    );
    map.insert(
        "input.transfer.amount".into(),
        vec![fe_from_field(&inputs.transfer_amount)],
    );
    map.insert(
        "input.transfer.fee".into(),
        vec![fe_from_field(&inputs.fee_amount)],
    );
    map.insert(
        "input.receiver.assets_tokens".into(),
        inputs.receiver_tokens.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.receiver.assets_amounts".into(),
        inputs.receiver_amounts.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.receiver.recipient_pk_x".into(),
        vec![fe_from_field_bytes(&inputs.recipient_pkx_be)],
    );
    map.insert(
        "input.receiver.salt".into(),
        vec![fe_from_field(&inputs.receiver_salt)],
    );
    map.insert(
        "input.remainder.assets_tokens".into(),
        inputs.remainder_tokens.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.remainder.assets_amounts".into(),
        inputs.remainder_amounts.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.remainder.recipient_pk_x".into(),
        vec![fe_from_field_bytes(&inputs.sender_pkx_be)],
    );
    map.insert(
        "input.remainder.salt".into(),
        vec![fe_from_field(&inputs.remainder_salt)],
    );

    SpendPrepared {
        abi_inputs: map,
        receiver_commit,
        remainder_commit,
        digest,
        msg32,
    }
}

/// Internal representation of the Noir `MergeInput` struct.
struct MergeInputs {
    sender_pkx_be: [u8; 32],
    sender_pky_be: [u8; 32],
    in0_tokens: [Field; 4],
    in0_amounts: [Field; 4],
    in0_salt: Field,
    in1_tokens: [Field; 4],
    in1_amounts: [Field; 4],
    in1_salt: Field,
    out_tokens: [Field; 4],
    out_amounts: [Field; 4],
    out_salt: Field,
}

/// Packed merge inputs alongside the derived commitment/digest.
struct MergePrepared {
    /// Noir-style ABI map (`input.*` keys) ready for `prove_with_all_inputs`.
    abi_inputs: HashMap<String, Vec<FE>>,
    /// Expected output commitment (circuits expose this publicly).
    out_commit: Field,
    /// Full Poseidon2 digest representing the transaction pre-hash.
    digest: Field,
    /// Digest truncated to 32 bytes (what Schnorr signs).
    msg32: [u8; 32],
}

/// Serialise the merge inputs into Noir ABI order and compute commitments.
///
/// As with `pack_spend_inputs`, this is the only location that knows about the
/// Noir field names. The resulting map can be fed directly into
/// `prove_with_all_inputs` to create the witness vector for the merge circuit.
#[allow(clippy::indexing_slicing)]
fn pack_merge_inputs(inputs: MergeInputs) -> MergePrepared {
    let out_utxo = Utxo {
        assets: array_init::array_init(|idx| Asset {
            token: inputs.out_tokens[idx],
            amount: inputs.out_amounts[idx],
        }),
        recipient_pk_x: Field::from_bytes(inputs.sender_pkx_be),
        salt: inputs.out_salt,
    };
    let out_commit = out_utxo.commitment();

    let digest = hash_fields(&[
        Field::from(2u128),
        Field::from_bytes(inputs.sender_pkx_be),
        out_commit,
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ]);
    let msg32 = digest.to_bytes();

    let mut map: HashMap<String, Vec<FE>> = HashMap::new();
    map.insert(
        "input.schnorr.pk_x".into(),
        vec![fe_from_field_bytes(&inputs.sender_pkx_be)],
    );
    map.insert(
        "input.schnorr.pk_y".into(),
        vec![fe_from_field_bytes(&inputs.sender_pky_be)],
    );
    map.insert(
        "input.schnorr.msg32".into(),
        msg32.iter().map(|b| fe_from_u8(*b)).collect(),
    );
    map.insert(
        "input.in0.assets_tokens".into(),
        inputs.in0_tokens.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.in0.assets_amounts".into(),
        inputs.in0_amounts.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.in0.recipient_pk_x".into(),
        vec![fe_from_field_bytes(&inputs.sender_pkx_be)],
    );
    map.insert(
        "input.in0.salt".into(),
        vec![fe_from_field(&inputs.in0_salt)],
    );
    map.insert(
        "input.in1.assets_tokens".into(),
        inputs.in1_tokens.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.in1.assets_amounts".into(),
        inputs.in1_amounts.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.in1.recipient_pk_x".into(),
        vec![fe_from_field_bytes(&inputs.sender_pkx_be)],
    );
    map.insert(
        "input.in1.salt".into(),
        vec![fe_from_field(&inputs.in1_salt)],
    );
    map.insert(
        "input.out.assets_tokens".into(),
        inputs.out_tokens.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.out.assets_amounts".into(),
        inputs.out_amounts.iter().map(fe_from_field).collect(),
    );
    map.insert(
        "input.out.recipient_pk_x".into(),
        vec![fe_from_field_bytes(&inputs.sender_pkx_be)],
    );
    map.insert(
        "input.out.salt".into(),
        vec![fe_from_field(&inputs.out_salt)],
    );

    MergePrepared {
        abi_inputs: map,
        out_commit,
        digest,
        msg32,
    }
}

/// Precompute spend commitments and digest without invoking a proof.
/// Return the expected spend commitments and digest without proving.
///
/// This utility mirrors the in-circuit hash computation and is mainly used by
/// tests or callers that need to pre-compute hashes before invoking the actual
/// prover. The returned tuple is `(receiver_commit, remainder_commit, digest,
/// msg32)`.
pub fn spend_commitments(
    sender_pk_x: Field,
    receiver: &Utxo,
    remainder: &Utxo,
    transfer_token: Field,
    transfer_amount: Field,
    fee_amount: Field,
) -> (Field, Field, Field, [u8; 32]) {
    let receiver_commit = receiver.commitment();
    let remainder_commit = remainder.commitment();
    let digest = hash_fields(&[
        Field::from(1u128),
        sender_pk_x,
        transfer_token,
        transfer_amount,
        fee_amount,
        receiver_commit,
        remainder_commit,
    ]);
    (receiver_commit, remainder_commit, digest, digest.to_bytes())
}

/// Precompute merge commitment and digest without invoking a proof.
/// Return the expected merge commitment and digest without proving.
pub fn merge_commitment(sender_pk_x: Field, out: &Utxo) -> (Field, Field, [u8; 32]) {
    let out_commit = out.commitment();
    let digest = hash_fields(&[
        Field::from(2u128),
        sender_pk_x,
        out_commit,
        Field::from(0u128),
        Field::from(0u128),
        Field::from(0u128),
    ]);
    (out_commit, digest, digest.to_bytes())
}
