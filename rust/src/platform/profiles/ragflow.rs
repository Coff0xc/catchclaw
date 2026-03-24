use crate::platform::*;

pub struct RagFlowProfile;

impl PlatformProfile for RagFlowProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::RagFlow }
    fn name(&self) -> &str { "RagFlow" }

    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            has_chat_completion: true,
            has_websocket: false,
            has_file_upload: true,
            has_admin_panel: true,
            has_plugin_system: true,
            has_workflow_engine: true,
            has_rag_pipeline: true,
            has_oauth: false,
            has_webhook: false,
            has_audio: false,
            has_mcp: false,
        }
    }

    fn resolve(&self, kind: EndpointKind) -> Option<Endpoint> {
        match kind {
            EndpointKind::ChatCompletion => Some(Endpoint::post("/v1/api/chat/completions")),
            EndpointKind::AuthLogin => Some(Endpoint::post("/api/auth/login")),
            EndpointKind::FileUpload => Some(Endpoint::post("/api/document/upload")),
            EndpointKind::DatasetList => Some(Endpoint::get("/api/kb/list")),
            EndpointKind::WorkflowRun => Some(Endpoint::post("/api/canvas/run")),
            EndpointKind::PluginMarket => Some(Endpoint::get("/api/plugin/list")),
            _ => None,
        }
    }

    fn fingerprint_markers(&self) -> FingerprintSpec {
        FingerprintSpec {
            body_keywords: vec!["RagFlow", "ragflow"],
            header_markers: vec![],
            probe_endpoints: vec![
                ProbeEndpoint {
                    path: "/api/auth/login",
                    method: "POST",
                    accept_statuses: vec![200, 401, 405],
                    body_contains: None,
                },
            ],
        }
    }

    fn default_ports(&self) -> &[u16] { &[9380, 80, 443] }
}
