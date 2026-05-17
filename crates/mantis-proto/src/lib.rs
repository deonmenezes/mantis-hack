//! Generated protobuf and tonic types for the Mantis daemon API.
//!
//! The proto files live at `/proto/*.proto` in the workspace root.
//! `build.rs` compiles them on every change via `tonic-build`. The
//! generated code is exposed under [`v1`].

pub const SCHEMA_VERSION: u32 = 1;

pub mod v1 {
    tonic::include_proto!("mantis.v1");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_one_after_m0_4() {
        assert_eq!(SCHEMA_VERSION, 1);
    }
}
