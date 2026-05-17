//! ResultExport Custom Resource — request a report rendering and
//! delivery.

use serde::{Deserialize, Serialize};

use crate::{ObjectMeta, API_VERSION};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultExport {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: ResultExportSpec,
}

impl ResultExport {
    pub fn new(name: impl Into<String>, spec: ResultExportSpec) -> Self {
        Self {
            api_version: API_VERSION.into(),
            kind: "ResultExport".into(),
            metadata: ObjectMeta::new(name),
            spec,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultExportSpec {
    pub engagement_ref: String,
    pub format: ExportFormat,
    /// Destination ConfigMap name where the rendered output lands.
    pub destination_config_map: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Markdown,
    Sarif,
    Hackerone,
    Bugcrowd,
    Openvex,
    Pdf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_round_trip() {
        let r = ResultExport::new(
            "weekly-report",
            ResultExportSpec {
                engagement_ref: "acme-monitor".into(),
                format: ExportFormat::Sarif,
                destination_config_map: "weekly-sarif".into(),
            },
        );
        let yaml = serde_yaml_ng::to_string(&r).unwrap();
        let back: ResultExport = serde_yaml_ng::from_str(&yaml).unwrap();
        assert!(matches!(back.spec.format, ExportFormat::Sarif));
    }

    #[test]
    fn all_formats_round_trip() {
        for fmt in [
            ExportFormat::Markdown,
            ExportFormat::Sarif,
            ExportFormat::Hackerone,
            ExportFormat::Bugcrowd,
            ExportFormat::Openvex,
            ExportFormat::Pdf,
        ] {
            let r = ResultExport::new(
                "r",
                ResultExportSpec {
                    engagement_ref: "e".into(),
                    format: fmt,
                    destination_config_map: "cm".into(),
                },
            );
            let yaml = serde_yaml_ng::to_string(&r).unwrap();
            let _back: ResultExport = serde_yaml_ng::from_str(&yaml).unwrap();
        }
    }
}
