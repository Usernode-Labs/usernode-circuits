#[test]
fn embedded_catalog_initializes() {
    usernode_circuits::init_default_circuits().expect("load embedded circuits");
    let mut loaded = usernode_circuits::catalog::all_loaded();
    loaded.sort();
    assert!(loaded.contains(&"utxo_merge".to_string()));
    assert!(loaded.contains(&"utxo_spend".to_string()));
}

#[test]
fn embedded_catalog_init_is_thread_safe() {
    const THREADS: usize = 4;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            usernode_circuits::init_embedded_catalog()
        }));
    }
    for handle in handles {
        handle
            .join()
            .expect("thread join")
            .expect("init should succeed");
    }
}
