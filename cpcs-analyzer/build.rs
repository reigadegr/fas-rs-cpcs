use std::{env, fs, path::PathBuf, process::Command};

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=../cpcs-analyzer-ebpf");
    println!("cargo:rerun-if-changed=../cpcs-analyzer-common");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let ebpf_dir = manifest_dir.join("../cpcs-analyzer-ebpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let target_dir = out_dir.join("ebpf_target");
    fs::create_dir_all(&target_dir)?;

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .arg("build")
        .arg("--target")
        .arg("bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--target-dir")
        .arg(&target_dir)
        .env_remove("RUSTUP_TOOLCHAIN");

    #[cfg(not(debug_assertions))]
    cmd.arg("--release");

    let status = cmd
        .status()
        .context("failed to spawn cargo for ebpf build")?;
    if !status.success() {
        bail!("ebpf build failed with status: {status}");
    }

    Ok(())
}
