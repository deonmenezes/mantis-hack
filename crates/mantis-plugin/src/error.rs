use thiserror::Error;

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("manifest malformed: {0}")]
    Manifest(String),

    #[error(
        "plugin {plugin} requests capability {capability} but the workspace policy forbids it"
    )]
    CapabilityRefused { plugin: String, capability: String },

    #[error("schema version {got} not supported (max {max})")]
    UnsupportedSchema { got: u32, max: u32 },

    #[error("plugin {id} already loaded")]
    Duplicate { id: String },

    #[error("plugin {id} not found")]
    NotFound { id: String },
}
