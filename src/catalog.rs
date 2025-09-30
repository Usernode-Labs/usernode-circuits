use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use anyhow::Context;

use crate::artifacts;

#[derive(Clone)]
pub struct CircuitEntry {
    pub name: String,
    pub acir: Vec<u8>,
    pub vk: Vec<u8>,
    pub abi: Abi,
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

pub fn update_vk(name: &str, vk: &[u8]) {
    if let Some(entry) = cache().lock().unwrap().get_mut(name)
        && entry.vk.is_empty()
    {
        entry.vk = vk.to_vec();
    }
}

pub fn clear() {
    cache().lock().unwrap().clear();
}

pub fn init_embedded() -> anyhow::Result<()> {
    for embed in artifacts::embedded() {
        let abi: Abi = serde_json::from_str(embed.abi_json)
            .with_context(|| format!("parsing ABI for {}", embed.name))?;
        insert(CircuitEntry {
            name: embed.name.to_string(),
            acir: embed.acir.to_vec(),
            vk: embed.vk.to_vec(),
            abi,
        });
    }
    Ok(())
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
