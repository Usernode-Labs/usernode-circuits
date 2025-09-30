use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let name = args
        .next()
        .context("usage: write_vk <circuit-name> <acir-path> <abi-json> <vk-output>")?;
    let acir_path = PathBuf::from(
        args.next()
            .context("usage: write_vk <circuit-name> <acir-path> <abi-json> <vk-output>")?,
    );
    let abi_path = PathBuf::from(
        args.next()
            .context("usage: write_vk <circuit-name> <acir-path> <abi-json> <vk-output>")?,
    );
    let vk_path = PathBuf::from(
        args.next()
            .context("usage: write_vk <circuit-name> <acir-path> <abi-json> <vk-output>")?,
    );

    let acir = fs::read(&acir_path).with_context(|| format!("reading {acir_path:?}"))?;
    let abi_json =
        fs::read_to_string(&abi_path).with_context(|| format!("reading {abi_path:?}"))?;

    usernode_circuits::prover::init_circuit_from_artifacts(&name, &acir, &[], &abi_json)?;
    let vk = usernode_circuits::prover::regenerate_vk(&name)?;
    fs::write(&vk_path, &vk).with_context(|| format!("writing {vk_path:?}"))?;
    println!(
        "wrote verifying key for {name} ({bytes} bytes) to {vk_path:?}",
        bytes = vk.len()
    );
    Ok(())
}
