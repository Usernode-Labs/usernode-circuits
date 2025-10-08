use std::collections::HashMap;
use std::env;
use std::sync::OnceLock;

use acir::AcirField;
use acir::FieldElement;
use acir::native_types::{Witness, WitnessMap};
use acir_field::FieldElement as FE;
use acvm::pwg::{ACVM, ACVMStatus};
use anyhow::Context;
use aztec_barretenberg_rs::BarretenbergBlackBoxSolver;
use aztec_barretenberg_rs::{
    acvm_exec, batch_merge_h2, compile_mega, mega_public_inputs, mega_vk_hash, prove_with_id,
    set_crs_path, verify_with_id, write_vk_mega_honk,
};

use crate::barretenberg::with_bb_lock;
use crate::bn254;
use crate::catalog::{self, Abi, AbiType, CircuitEntry};

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

static EMBEDDED_INIT: OnceLock<anyhow::Result<Vec<CircuitEntry>>> = OnceLock::new();

pub fn init_embedded_catalog() -> anyhow::Result<()> {
    ensure_crs();
    let result = EMBEDDED_INIT.get_or_init(catalog::init_embedded);
    match result {
        Ok(entries) => {
            catalog::hydrate(entries);
            Ok(())
        }
        Err(err) => Err(anyhow::Error::msg(err.to_string())),
    }
}

pub fn insert_circuit(entry: CircuitEntry) {
    ensure_crs();
    catalog::insert(entry);
}

pub fn get_circuit(name: &str) -> Option<CircuitEntry> {
    catalog::get(name)
}

pub fn get_key_id(name: &str) -> anyhow::Result<[u8; 32]> {
    get_circuit(name)
        .map(|entry| entry.key_id)
        .ok_or_else(|| anyhow::anyhow!("circuit not initialized"))
}

pub fn get_vk_bytes_by_id(vk_id: [u8; 32]) -> anyhow::Result<Vec<u8>> {
    ensure_crs();
    if let Some(entry) = get_circuit_by_key_id(&vk_id) {
        if entry.vk.is_empty() {
            let vk = regenerate_vk(&entry.name)?;
            let refreshed = get_circuit(&entry.name).ok_or_else(|| {
                anyhow::anyhow!(
                    "circuit {name} missing after regeneration",
                    name = entry.name
                )
            })?;
            anyhow::ensure!(
                refreshed.key_id == vk_id,
                "verifying key id changed after regeneration for {}",
                entry.name
            );
            Ok(vk)
        } else {
            Ok(entry.vk)
        }
    } else if let Some(vk_entry) = catalog::get_vk_entry_by_id(&vk_id) {
        anyhow::ensure!(
            !vk_entry.bytes.is_empty(),
            "verifying key bytes missing for id {}",
            format_key_id(&vk_id)
        );
        Ok(vk_entry.bytes)
    } else {
        Err(anyhow::anyhow!(
            "unknown verifying key id {}",
            format_key_id(&vk_id)
        ))
    }
}

fn get_circuit_by_key_id(id: &[u8; 32]) -> Option<CircuitEntry> {
    for name in catalog::all_loaded() {
        if let Some(entry) = catalog::get(&name).filter(|entry| entry.key_id == *id) {
            return Some(entry);
        }
    }
    None
}

fn format_key_id(id: &[u8; 32]) -> String {
    let mut out = String::with_capacity(id.len().saturating_mul(2));
    for byte in id.iter() {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

pub fn get_vk_hash_by_id(vk_id: [u8; 32]) -> anyhow::Result<[u8; 32]> {
    ensure_crs();
    if let Some(entry) = get_circuit_by_key_id(&vk_id) {
        if let Some(hash) = entry.vk_hash {
            return Ok(hash);
        }
        let vk_bytes = get_vk_bytes_by_id(vk_id)?;
        let hash = mega_vk_hash(&vk_bytes)?;
        catalog::update_vk(&entry.name, &vk_bytes, Some(hash), None);
        return Ok(hash);
    }
    if let Some(vk_entry) = catalog::get_vk_entry_by_id(&vk_id) {
        if let Some(hash) = vk_entry.hash {
            return Ok(hash);
        }
        anyhow::ensure!(
            !vk_entry.bytes.is_empty(),
            "verifying key bytes missing for id {}",
            format_key_id(&vk_id)
        );
        let hash = mega_vk_hash(&vk_entry.bytes)?;
        catalog::upsert_vk_entry(vk_id, vk_entry.bytes, Some(hash));
        return Ok(hash);
    }
    Err(anyhow::anyhow!(
        "unknown verifying key id {}",
        format_key_id(&vk_id)
    ))
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
    let key_id =
        with_bb_lock(|| compile_mega(acir)).with_context(|| format!("compile_mega for {name}"))?;
    let mut vk_vec = vk.to_vec();
    if vk_vec.is_empty() {
        let generated = with_bb_lock(|| write_vk_mega_honk(acir))?;
        vk_vec = generated.0;
    }
    let vk_hash = if vk_vec.is_empty() {
        None
    } else {
        Some(mega_vk_hash(&vk_vec)?)
    };
    catalog::insert(CircuitEntry {
        name: name.to_string(),
        acir: acir.to_vec(),
        vk: vk_vec,
        abi,
        key_id,
        vk_hash,
    });
    Ok(())
}

pub fn regenerate_vk(name: &str) -> anyhow::Result<Vec<u8>> {
    let entry = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    let (vk, key_id) = with_bb_lock(|| {
        let id = compile_mega(&entry.acir)?;
        let vk = write_vk_mega_honk(&entry.acir)?;
        Ok::<_, anyhow::Error>((vk, id))
    })?;
    let vk_hash = aztec_barretenberg_rs::mega_vk_hash(&vk.0)?;
    catalog::update_vk(name, &vk.0, Some(vk_hash), Some(key_id));
    Ok(vk.0)
}

pub fn prove(name: &str, private_inputs: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
    let ent = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    let witness = acvm_exec::compute_witness_from_private_inputs(&ent.acir, private_inputs)?;
    let proof = with_bb_lock(|| prove_with_id(&ent.key_id, &witness.0))?;
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
    let proof = with_bb_lock(|| prove_with_id(&ent.key_id, &witness_bytes))?;
    Ok(proof.0)
}

pub fn verify(name: &str, proof: &[u8]) -> anyhow::Result<bool> {
    let ent = get_circuit(name).ok_or_else(|| anyhow::anyhow!("circuit not initialized"))?;
    let ok = with_bb_lock(|| verify_with_id(&ent.key_id, proof))?;
    Ok(ok)
}

pub fn merge_batch_h2_by_id(
    left_id: [u8; 32],
    left_proof: &[u8],
    right_id: [u8; 32],
    right_proof: &[u8],
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    ensure_crs();
    let left_vk = get_vk_bytes_by_id(left_id)?;
    let right_vk = get_vk_bytes_by_id(right_id)?;
    let (proof, merged_vk) = batch_merge_h2(left_proof, &left_vk, right_proof, &right_vk)
        .with_context(|| "batch merge h2 by id")?;
    let merged_vk_bytes = merged_vk.0;
    let merged_vk_id =
        mega_vk_hash(&merged_vk_bytes).with_context(|| "hash merged verifying key")?;
    catalog::upsert_vk_entry(merged_vk_id, merged_vk_bytes, Some(merged_vk_id));
    Ok((proof.0, merged_vk_id))
}

pub fn fetch_batch_public_inputs(proof: &[u8], vk_id: [u8; 32]) -> anyhow::Result<Vec<[u8; 32]>> {
    ensure_crs();
    let vk_bytes = get_vk_bytes_by_id(vk_id)?;
    let raw_inputs = mega_public_inputs(proof, &vk_bytes).with_context(|| {
        format!(
            "fetch public inputs with verifying key id {}",
            format_key_id(&vk_id)
        )
    })?;
    anyhow::ensure!(
        raw_inputs.len() % 32 == 0,
        "public inputs length {} not a multiple of 32 bytes",
        raw_inputs.len()
    );
    let mut inputs = Vec::with_capacity(raw_inputs.len() / 32);
    for chunk in raw_inputs.chunks(32) {
        let mut elem = [0u8; 32];
        elem.copy_from_slice(chunk);
        inputs.push(elem);
    }
    Ok(inputs)
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
    let proof = with_bb_lock(|| prove_with_id(&ent.key_id, &witness.0))?;
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
    let proof = with_bb_lock(|| prove_with_id(&ent.key_id, &witness.0))?;
    Ok(proof.0)
}
