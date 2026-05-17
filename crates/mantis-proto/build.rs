fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Path is relative to the crate root (crates/mantis-proto).
    println!("cargo:rerun-if-changed=../../proto/engagement.proto");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["../../proto/engagement.proto"], &["../../proto"])?;
    Ok(())
}
