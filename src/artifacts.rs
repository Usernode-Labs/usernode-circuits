pub struct EmbeddedCircuit {
    pub name: &'static str,
    pub acir: &'static [u8],
    pub vk: &'static [u8],
    pub abi_json: &'static str,
}

pub fn embedded() -> &'static [EmbeddedCircuit] {
    static CIRCUITS: &[EmbeddedCircuit] = &[
        EmbeddedCircuit {
            name: "utxo_spend",
            acir: include_bytes!("../artifacts/utxo_spend.acir"),
            vk: include_bytes!("../artifacts/utxo_spend.vk"),
            abi_json: include_str!("../artifacts/utxo_spend.abi.json"),
        },
        EmbeddedCircuit {
            name: "utxo_merge",
            acir: include_bytes!("../artifacts/utxo_merge.acir"),
            vk: include_bytes!("../artifacts/utxo_merge.vk"),
            abi_json: include_str!("../artifacts/utxo_merge.abi.json"),
        },
    ];
    CIRCUITS
}
