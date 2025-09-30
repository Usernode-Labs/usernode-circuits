#[test]
fn embedded_catalog_initializes() {
    usernode_circuits::init_default_circuits().expect("load embedded circuits");
    let mut loaded = usernode_circuits::catalog::all_loaded();
    loaded.sort();
    assert!(loaded.contains(&"utxo_merge".to_string()));
    assert!(loaded.contains(&"utxo_spend".to_string()));
}
