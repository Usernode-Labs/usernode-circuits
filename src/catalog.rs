use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use anyhow::Context;

use crate::artifacts;
use crate::barretenberg::with_bb_lock;

#[derive(Clone)]
pub struct CircuitEntry {
    pub name: String,
    pub acir: Vec<u8>,
    pub vk: Vec<u8>,
    pub abi: Abi,
    pub key_id: [u8; 32],
    pub vk_hash: Option<[u8; 32]>,
}

static CACHE: OnceLock<Mutex<HashMap<String, CircuitEntry>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, CircuitEntry>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn all_loaded() -> Vec<String> {
    cache().lock().unwrap().keys().cloned().collect()
}

pub fn get(name: &str) -> Option<CircuitEntry> {
    cache().lock().unwrap().get(name).cloned()
}

pub fn insert(entry: CircuitEntry) {
    cache().lock().unwrap().insert(entry.name.clone(), entry);
}

pub fn update_vk(name: &str, vk: &[u8], vk_hash: Option<[u8; 32]>, key_id: Option<[u8; 32]>) {
    if let Some(entry) = cache().lock().unwrap().get_mut(name) {
        if entry.vk.is_empty() || entry.vk != vk {
            entry.vk = vk.to_vec();
        }
        if entry.vk_hash != vk_hash {
            entry.vk_hash = vk_hash;
        }
        if let Some(id) = key_id {
            entry.key_id = id;
        }
    }
}

pub fn clear() {
    cache().lock().unwrap().clear();
}

pub fn hydrate(entries: &[CircuitEntry]) {
    let mut cache = cache().lock().unwrap();
    for entry in entries {
        cache.insert(entry.name.clone(), entry.clone());
    }
}

pub fn init_embedded() -> anyhow::Result<Vec<CircuitEntry>> {
    let mut entries = Vec::new();
    let mut cache_guard = cache().lock().unwrap();
    for embed in artifacts::embedded() {
        let abi: Abi = serde_json::from_str(embed.abi_json)
            .with_context(|| format!("parsing ABI for {}", embed.name))?;
        let key_id = with_bb_lock(|| aztec_barretenberg_rs::compile_mega(embed.acir))
            .with_context(|| format!("compile_mega for {}", embed.name))?;
        let vk_vec = embed.vk.to_vec();
        let vk_hash = if vk_vec.is_empty() {
            None
        } else {
            Some(
                aztec_barretenberg_rs::mega_vk_hash(&vk_vec)
                    .with_context(|| format!("vk hash for {}", embed.name))?,
            )
        };
        let entry = CircuitEntry {
            name: embed.name.to_string(),
            acir: embed.acir.to_vec(),
            vk: vk_vec,
            abi,
            key_id,
            vk_hash,
        };
        cache_guard.insert(entry.name.clone(), entry.clone());
        entries.push(entry);
    }
    Ok(entries)
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Abi {
    pub parameters: Vec<AbiParam>,
    #[allow(dead_code)]
    pub return_type: Option<AbiReturn>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub abi_type: AbiType,
    pub visibility: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct AbiReturn {
    pub abi_type: AbiType,
    pub visibility: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct AbiStructField {
    pub name: String,
    #[serde(rename = "type")]
    pub abi_type: AbiType,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AbiType {
    Field,
    Array {
        length: usize,
        #[serde(rename = "type")]
        elem: Box<AbiType>,
    },
    Integer {
        sign: String,
        width: u32,
    },
    Boolean,
    Struct {
        fields: Vec<AbiStructField>,
    },
}
