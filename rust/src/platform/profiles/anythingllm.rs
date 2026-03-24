use crate::platform::*;

pub struct AnythingLLMProfile;

impl PlatformProfile for AnythingLLMProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::AnythingLLM }
    fn name(&self) -> &str { "AnythingLLM" }

    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            has_chat_completion: true,
            has_websocket: false,
            has_file_upload: true,
            has_admin_panel: true,
            has_plugin_system: true,
            has_workflow_engine: false,
            has_rag_pipeline: true,
            has_oauth: false,
            has_webhook: false,
            has_audio: false,
            has_mcp: false,
        }
    }

    fn resolve(&self, kind: EndpointKind) -> Option<Endpoint> {
        match kind {
            EndpointKind::ChatCompletion => Some(Endpoint::post("/api/v1/workspace/{slug}/chat")),
            EndpointKind::SystemConfig => Some(Endpoint::get("/api/v1/system/env")),
            EndpointKind::SystemHealth => Some(Endpoint::get("/api/ping")),
            EndpointKind::AuthLogin => Some(Endpoint::post("/api/v1/auth")),
            EndpointKind::FileUpload => Some(Endpoint::post("/api/v1/document/upload")),
            EndpointKind::DatasetList => Some(Endpoint::get("/api/v1/documents")),
            EndpointKind::PluginMarket => Some(Endpoint::get("/api/v1/extensions")),
            _ => None,
        }
    }

    fn fingerprint_markers(&self) -> FingerprintSpec {
        FingerprintSpec {
            body_keywords: vec!["AnythingLLM", "anythingllm"],
            header_markers: vec![],
            probe_endpoints: vec![
                ProbeEndpoint {
                    path: "/api/ping",
                    method: "GET",
                    accept_statuses: vec![200],
                    body_contains: None,
                },
            ],
        }
    }

    fn default_ports(&self) -> &[u16] { &[3001, 3000, 80] }
}
