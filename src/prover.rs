use std::collections::HashMap;
use std::env;
use std::sync::{Mutex, OnceLock};

use acir::AcirField;
use acir::FieldElement;
use acir::native_types::{Witness, WitnessMap};
use acir_field::FieldElement as FE;
use acvm::pwg::{ACVM, ACVMStatus};
use anyhow::Context;
use aztec_barretenberg_rs::BarretenbergBlackBoxSolver;
use aztec_barretenberg_rs::{
    acvm_exec, batch_merge_h2, merge_mega, prove_mega_honk, set_crs_path, verify_mega_honk,
    write_vk_mega_honk,
};

use crate::bn254;
use crate::catalog::{self, Abi, AbiType, CircuitEntry};

static BB_GUARD: OnceLock<Mutex<()>> = OnceLock::new();

fn bb_lock() -> std::sync::MutexGuard<'static, ()> {
    BB_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("barretenberg mutex poisoned")
}

fn ensure_crs() {
    static CRS_INIT: OnceLock<()> = OnceLock::new();
    CRS_INIT.get_or_init(|| {
        let dir = env::var("BB_CRS_DIR")
            .ok()
            .or_else(|| dirs::home_dir().map(|h| h.join(".bb-crs").to_string_lossy().to_string()))
            .unwrap_or_else(|| ".bb-crs".to_owned());
        let _ = set_crs_path(&dir);
    });
}

pub fn init_embedded_catalog() -> anyhow::Result<()> {
    ensure_crs();
    catalog::init_embedded()
}

pub fn insert_circuit(entry: CircuitEntry) {
    ensure_crs();
    catalog::insert(entry);
}

pub fn get_circuit(name: &str) -> Option<CircuitEntry> {
    catalog::get(name)
}

pub fn init_circuit_from_artifacts(
    name: &str,
    acir: &[u8],
    vk: &[u8],
    abi_json: &str,
) -> anyhow::Result<()> {
    ensure_crs();
    let abi: Abi =
        serde_json::from_str(abi_json).with_context(|| format!("parsing ABI for {name}"))?;
    catalog::insert(CircuitEntry {
        name: name.to_string(),
        acir: acir.to_vec(),
        vk: vk.to_vec(),
        abi,
    });
    Ok(())
}

pub fn regenerate_vk(name: &str) -> anyhow::Result<Vec<u8>> {
    let entry = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    let vk = {
        let _guard = bb_lock();
        write_vk_mega_honk(&entry.acir)
    }?;
    catalog::update_vk(name, &vk.0);
    Ok(vk.0)
}

pub fn prove(name: &str, private_inputs: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
    let ent = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    let witness = acvm_exec::compute_witness_from_private_inputs(&ent.acir, private_inputs)?;
    let (proof, vk_from_prove) = {
        let _g = bb_lock();
        prove_mega_honk(&ent.acir, &witness.0)
    }?;
    catalog::update_vk(name, &vk_from_prove.0);
    Ok(proof.0)
}

pub fn prove_with_priv_and_pub(
    name: &str,
    private_inputs: &[FieldElement],
    public_inputs: &[FieldElement],
) -> anyhow::Result<Vec<u8>> {
    let ent = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    let program: acir::circuit::Program<FieldElement> =
        match acir::circuit::Program::deserialize_program(&ent.acir) {
            Ok(p) => p,
            Err(_) => bincode::deserialize(&ent.acir)?,
        };
    anyhow::ensure!(!program.functions.is_empty(), "empty program");
    let func = program
        .functions
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing function in program"))?;

    let mut initial = WitnessMap::new();
    {
        let mut indices: Vec<u32> = func
            .private_parameters
            .iter()
            .map(|w| match *w {
                Witness(idx) => idx,
            })
            .collect();
        indices.sort_unstable();
        anyhow::ensure!(
            private_inputs.len() <= indices.len(),
            "too many private inputs"
        );
        for (idx, fe) in indices.iter().zip(private_inputs.iter()) {
            initial.insert(Witness(*idx), *fe);
        }
    }
    {
        let mut indices: Vec<u32> = func
            .public_parameters
            .0
            .iter()
            .map(|w| match *w {
                Witness(idx) => idx,
            })
            .collect();
        indices.sort_unstable();
        anyhow::ensure!(
            public_inputs.len() <= indices.len(),
            "too many public inputs"
        );
        for (idx, fe) in indices.iter().zip(public_inputs.iter()) {
            initial.insert(Witness(*idx), *fe);
        }
    }

    let solver = BarretenbergBlackBoxSolver;
    let mut acvm: ACVM<'_, FieldElement, _> = ACVM::new(
        &solver,
        &func.opcodes,
        initial,
        &program.unconstrained_functions,
        &func.assert_messages,
    );
    loop {
        match acvm.solve() {
            ACVMStatus::Solved => break,
            ACVMStatus::RequiresForeignCall(_) | ACVMStatus::RequiresAcirCall(_) => {
                anyhow::bail!("unsupported: foreign/acir call in ACVM")
            }
            ACVMStatus::Failure(e) => anyhow::bail!("acvm failure: {e:?}"),
            ACVMStatus::InProgress => continue,
        }
    }
    let witness_map = acvm.finalize();
    let stack: acir::native_types::WitnessStack<FieldElement> = witness_map.into();
    let gz = stack
        .serialize()
        .map_err(|_| anyhow::anyhow!("witness stack serialize"))?;
    let mut dec = flate2::read::GzDecoder::new(gz.as_slice());
    let mut witness_bytes = Vec::new();
    use std::io::Read;
    dec.read_to_end(&mut witness_bytes)
        .map_err(|_| anyhow::anyhow!("gunzip witness stack"))?;
    let (proof, vk_from_prove) = {
        let _g = bb_lock();
        prove_mega_honk(&ent.acir, &witness_bytes)
    }?;
    catalog::update_vk(name, &vk_from_prove.0);
    Ok(proof.0)
}

pub fn verify(name: &str, proof: &[u8]) -> anyhow::Result<bool> {
    let ent = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    let ok = {
        let _g = bb_lock();
        verify_mega_honk(proof, &ent.vk)
    }?;
    Ok(ok)
}

pub fn merge_proofs_by_name(
    left_name: &str,
    left_proof: &[u8],
    right_name: &str,
    right_proof: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let left =
        get_circuit(left_name).ok_or_else(|| anyhow::anyhow!("left circuit not initialized"))?;
    let right =
        get_circuit(right_name).ok_or_else(|| anyhow::anyhow!("right circuit not initialized"))?;
    let (proof, vk) = merge_mega(left_proof, &left.vk, right_proof, &right.vk)?;
    Ok((proof.0, vk.0))
}

pub fn merge_batch_h2_by_name(
    left_name: &str,
    left_proof: &[u8],
    right_name: &str,
    right_proof: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let left =
        get_circuit(left_name).ok_or_else(|| anyhow::anyhow!("left circuit not initialized"))?;
    let right =
        get_circuit(right_name).ok_or_else(|| anyhow::anyhow!("right circuit not initialized"))?;
    let (proof, vk) = batch_merge_h2(left_proof, &left.vk, right_proof, &right.vk)?;
    Ok((proof.0, vk.0))
}

pub fn merge_batch_h2(
    left_proof: &[u8],
    left_vk: &[u8],
    right_proof: &[u8],
    right_vk: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (proof, vk) = batch_merge_h2(left_proof, left_vk, right_proof, right_vk)?;
    Ok((proof.0, vk.0))
}

pub fn init_default_circuits() -> anyhow::Result<()> {
    init_embedded_catalog()
}

pub fn public_outputs(
    name: &str,
    private_inputs: &[FieldElement],
) -> anyhow::Result<Vec<bn254::Field>> {
    let ent = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    let program: acir::circuit::Program<FieldElement> =
        match acir::circuit::Program::deserialize_program(&ent.acir) {
            Ok(p) => p,
            Err(_) => bincode::deserialize(&ent.acir)?,
        };
    anyhow::ensure!(!program.functions.is_empty(), "empty program");
    let func = program
        .functions
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing function in program"))?;

    let mut indices: Vec<u32> = func
        .private_parameters
        .iter()
        .map(|w| match *w {
            Witness(idx) => idx,
        })
        .collect();
    indices.sort_unstable();
    anyhow::ensure!(
        private_inputs.len() <= indices.len(),
        "too many private inputs"
    );

    let mut initial = WitnessMap::new();
    for (idx, fe) in indices.iter().zip(private_inputs.iter()) {
        initial.insert(Witness(*idx), *fe);
    }

    let solver = BarretenbergBlackBoxSolver;
    let mut acvm: ACVM<'_, FieldElement, _> = ACVM::new(
        &solver,
        &func.opcodes,
        initial,
        &program.unconstrained_functions,
        &func.assert_messages,
    );
    loop {
        match acvm.solve() {
            ACVMStatus::Solved => break,
            ACVMStatus::RequiresForeignCall(_) | ACVMStatus::RequiresAcirCall(_) => {
                anyhow::bail!("unsupported: foreign/acir call in ACVM")
            }
            ACVMStatus::Failure(e) => anyhow::bail!("acvm failure: {e:?}"),
            ACVMStatus::InProgress => continue,
        }
    }
    let map = acvm.finalize();
    let mut outs = Vec::new();
    for w in func.return_values.0.iter() {
        let Witness(idx) = *w;
        let fe = map
            .get(&Witness(idx))
            .ok_or_else(|| anyhow::anyhow!("missing witness {idx}"))?;
        let be = fe.to_be_bytes();
        let start = be
            .len()
            .checked_sub(32)
            .ok_or_else(|| anyhow::anyhow!("witness bytes shorter than 32"))?;
        let tail = be
            .get(start..)
            .ok_or_else(|| anyhow::anyhow!("missing 32-byte tail"))?;
        anyhow::ensure!(tail.len() == 32, "expected 32-byte field tail");
        let mut b32 = [0u8; 32];
        b32.copy_from_slice(tail);
        outs.push(bn254::Field::from_bytes(b32));
    }
    Ok(outs)
}

fn fe_from_field_bytes(be32: &[u8; 32]) -> FE {
    FE::from_be_bytes_reduce(be32)
}

fn fe_from_field(f: &bn254::Field) -> FE {
    fe_from_field_bytes(f.as_ref())
}

fn fe_from_u8(v: u8) -> FE {
    acir_field::FieldElement::from(v as u128)
}

pub struct SchnorrEnc {
    pub pk_x: [u8; 32],
    pub pk_y: [u8; 32],
    pub sig64: [u8; 64],
    pub msg32: [u8; 32],
}

pub struct UtxoEnc {
    pub assets_tokens: [bn254::Field; 4],
    pub assets_amounts: [bn254::Field; 4],
    pub recipient_pk_x: [u8; 32],
    pub salt: bn254::Field,
}

pub struct TransferEnc {
    pub token: bn254::Field,
    pub amount: bn254::Field,
    pub fee: bn254::Field,
}

pub struct SpendInputEnc {
    pub schnorr: SchnorrEnc,
    pub in0: UtxoEnc,
    pub transfer: TransferEnc,
    pub receiver: UtxoEnc,
    pub remainder: UtxoEnc,
}

pub struct MergeInputEnc {
    pub schnorr: SchnorrEnc,
    pub in0: UtxoEnc,
    pub in1: UtxoEnc,
    pub out: UtxoEnc,
}

pub fn encode_spend_privates(enc: &SpendInputEnc) -> Vec<FE> {
    let mut v: Vec<FE> = Vec::new();
    v.push(fe_from_field_bytes(&enc.schnorr.pk_x));
    v.push(fe_from_field_bytes(&enc.schnorr.pk_y));
    v.extend(enc.schnorr.sig64.iter().map(|b| fe_from_u8(*b)));
    v.extend(enc.schnorr.msg32.iter().map(|b| fe_from_u8(*b)));
    v.extend(enc.in0.assets_tokens.iter().map(fe_from_field));
    v.extend(enc.in0.assets_amounts.iter().map(fe_from_field));
    v.push(fe_from_field_bytes(&enc.in0.recipient_pk_x));
    v.push(fe_from_field(&enc.in0.salt));
    v.push(fe_from_field(&enc.transfer.token));
    v.push(fe_from_field(&enc.transfer.amount));
    v.push(fe_from_field(&enc.transfer.fee));
    v.extend(enc.receiver.assets_tokens.iter().map(fe_from_field));
    v.extend(enc.receiver.assets_amounts.iter().map(fe_from_field));
    v.push(fe_from_field_bytes(&enc.receiver.recipient_pk_x));
    v.push(fe_from_field(&enc.receiver.salt));
    v.extend(enc.remainder.assets_tokens.iter().map(fe_from_field));
    v.extend(enc.remainder.assets_amounts.iter().map(fe_from_field));
    v.push(fe_from_field_bytes(&enc.remainder.recipient_pk_x));
    v.push(fe_from_field(&enc.remainder.salt));
    v
}

pub fn encode_merge_privates(enc: &MergeInputEnc) -> Vec<FE> {
    let mut v: Vec<FE> = Vec::new();
    v.push(fe_from_field_bytes(&enc.schnorr.pk_x));
    v.push(fe_from_field_bytes(&enc.schnorr.pk_y));
    v.extend(enc.schnorr.sig64.iter().map(|b| fe_from_u8(*b)));
    v.extend(enc.schnorr.msg32.iter().map(|b| fe_from_u8(*b)));
    v.extend(enc.in0.assets_tokens.iter().map(fe_from_field));
    v.extend(enc.in0.assets_amounts.iter().map(fe_from_field));
    v.push(fe_from_field_bytes(&enc.in0.recipient_pk_x));
    v.push(fe_from_field(&enc.in0.salt));
    v.extend(enc.in1.assets_tokens.iter().map(fe_from_field));
    v.extend(enc.in1.assets_amounts.iter().map(fe_from_field));
    v.push(fe_from_field_bytes(&enc.in1.recipient_pk_x));
    v.push(fe_from_field(&enc.in1.salt));
    v.extend(enc.out.assets_tokens.iter().map(fe_from_field));
    v.extend(enc.out.assets_amounts.iter().map(fe_from_field));
    v.push(fe_from_field_bytes(&enc.out.recipient_pk_x));
    v.push(fe_from_field(&enc.out.salt));
    v
}

pub fn prove_with_abi(
    name: &str,
    inputs_by_name: &HashMap<String, Vec<FE>>,
) -> anyhow::Result<Vec<u8>> {
    let ent = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    fn push_param(
        acc: &mut Vec<FE>,
        abi_type: &AbiType,
        name: &str,
        inputs_by_name: &HashMap<String, Vec<FE>>,
    ) -> anyhow::Result<()> {
        match abi_type {
            AbiType::Field => {
                let v = inputs_by_name
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!(format!("missing input for param {name}")))?;
                anyhow::ensure!(v.len() == 1, "param {name} expects 1 field element");
                if let Some(x) = v.first() {
                    acc.push(*x);
                } else {
                    anyhow::bail!("param {name} expects 1 element");
                }
            }
            AbiType::Array { length, elem } => {
                let v = inputs_by_name
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!(format!("missing input for param {name}")))?;
                anyhow::ensure!(
                    v.len() == *length,
                    "param {name} expects array length {length}, got {}",
                    v.len()
                );
                match &**elem {
                    AbiType::Field | AbiType::Integer { .. } | AbiType::Boolean => {
                        acc.extend_from_slice(v);
                    }
                    AbiType::Array { .. } => {
                        anyhow::bail!("nested arrays not supported in this helper: {name}");
                    }
                    AbiType::Struct { .. } => {
                        anyhow::bail!("arrays of structs not supported in this helper: {name}");
                    }
                }
            }
            AbiType::Integer { .. } | AbiType::Boolean => {
                let v = inputs_by_name
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!(format!("missing input for param {name}")))?;
                anyhow::ensure!(v.len() == 1, "param {name} expects 1 element");
                if let Some(x) = v.first() {
                    acc.push(*x);
                } else {
                    anyhow::bail!("param {name} expects 1 element");
                }
            }
            AbiType::Struct { fields } => {
                for f in fields {
                    let child = format!("{name}.{}", f.name);
                    push_param(acc, &f.abi_type, &child, inputs_by_name)?;
                }
            }
        }
        Ok(())
    }

    let mut private_inputs: Vec<FE> = Vec::new();
    for p in &ent.abi.parameters {
        if p.visibility == "private" {
            push_param(&mut private_inputs, &p.abi_type, &p.name, inputs_by_name)?;
        }
    }

    let witness = acvm_exec::compute_witness_from_private_inputs(&ent.acir, &private_inputs)?;
    let (proof, vk_from_prove) = {
        let _g = bb_lock();
        prove_mega_honk(&ent.acir, &witness.0)
    }?;
    catalog::update_vk(name, &vk_from_prove.0);
    Ok(proof.0)
}

pub fn prove_with_all_inputs(
    name: &str,
    inputs_by_name: &HashMap<String, Vec<FE>>,
) -> anyhow::Result<Vec<u8>> {
    let ent = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    fn push_param(
        acc: &mut Vec<FE>,
        abi_type: &AbiType,
        name: &str,
        inputs_by_name: &HashMap<String, Vec<FE>>,
    ) -> anyhow::Result<()> {
        match abi_type {
            AbiType::Field => {
                let v = inputs_by_name
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!(format!("missing input for param {name}")))?;
                anyhow::ensure!(v.len() == 1, "param {name} expects 1 field element");
                if let Some(x) = v.first() {
                    acc.push(*x);
                } else {
                    anyhow::bail!("param {name} expects 1 element");
                }
            }
            AbiType::Array { length, elem } => {
                let v = inputs_by_name
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!(format!("missing input for param {name}")))?;
                anyhow::ensure!(
                    v.len() == *length,
                    "param {name} expects array length {length}, got {}",
                    v.len()
                );
                match &**elem {
                    AbiType::Field | AbiType::Integer { .. } | AbiType::Boolean => {
                        acc.extend_from_slice(v);
                    }
                    AbiType::Array { .. } => {
                        anyhow::bail!("nested arrays not supported in this helper: {name}");
                    }
                    AbiType::Struct { .. } => {
                        anyhow::bail!("arrays of structs not supported in this helper: {name}");
                    }
                }
            }
            AbiType::Integer { .. } | AbiType::Boolean => {
                let v = inputs_by_name
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!(format!("missing input for param {name}")))?;
                anyhow::ensure!(v.len() == 1, "param {name} expects 1 element");
                if let Some(x) = v.first() {
                    acc.push(*x);
                } else {
                    anyhow::bail!("param {name} expects 1 element");
                }
            }
            AbiType::Struct { fields } => {
                for f in fields {
                    let child = format!("{name}.{}", f.name);
                    push_param(acc, &f.abi_type, &child, inputs_by_name)?;
                }
            }
        }
        Ok(())
    }

    let mut all_inputs: Vec<FE> = Vec::new();
    for p in &ent.abi.parameters {
        if p.visibility == "private" {
            push_param(&mut all_inputs, &p.abi_type, &p.name, inputs_by_name)?;
        }
    }

    let witness = acvm_exec::compute_witness_from_private_inputs(&ent.acir, &all_inputs)?;
    let (proof, vk_from_prove) = {
        let _g = bb_lock();
        prove_mega_honk(&ent.acir, &witness.0)
    }?;
    catalog::update_vk(name, &vk_from_prove.0);
    Ok(proof.0)
}
