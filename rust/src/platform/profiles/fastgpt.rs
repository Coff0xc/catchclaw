use crate::platform::*;

pub struct FastGPTProfile;

impl PlatformProfile for FastGPTProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::FastGPT }
    fn name(&self) -> &str { "FastGPT" }

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
            EndpointKind::ChatCompletion => Some(Endpoint::post("/api/v1/chat/completions")),
            EndpointKind::SystemConfig => Some(Endpoint::get("/api/system/getInitData")),
            EndpointKind::AuthLogin => Some(Endpoint::post("/api/support/user/account/login")),
            EndpointKind::FileUpload => Some(Endpoint::post("/api/core/dataset/collection/create/localFile")),
            EndpointKind::DatasetList => Some(Endpoint::get("/api/core/dataset/list")),
            EndpointKind::WorkflowRun => Some(Endpoint::post("/api/core/workflow/run")),
            EndpointKind::PluginMarket => Some(Endpoint::get("/api/marketplace/list")),
            _ => None,
        }
    }

    fn fingerprint_markers(&self) -> FingerprintSpec {
        FingerprintSpec {
            body_keywords: vec!["FastGPT", "fastgpt"],
            header_markers: vec![],
            probe_endpoints: vec![
                ProbeEndpoint {
                    path: "/api/system/getInitData",
                    method: "GET",
                    accept_statuses: vec![200],
                    body_contains: None,
                },
            ],
        }
    }

    fn default_ports(&self) -> &[u16] { &[3000, 80, 443] }
}
