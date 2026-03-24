use crate::platform::*;

pub struct DifyProfile;

impl PlatformProfile for DifyProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::Dify }
    fn name(&self) -> &str { "Dify" }

    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            has_chat_completion: true,
            has_websocket: false,
            has_file_upload: true,
            has_admin_panel: true,
            has_plugin_system: true,
            has_workflow_engine: true,
            has_rag_pipeline: true,
            has_oauth: true,
            has_webhook: false,
            has_audio: true,
            has_mcp: true,
        }
    }

    fn resolve(&self, kind: EndpointKind) -> Option<Endpoint> {
        match kind {
            EndpointKind::ChatCompletion => Some(Endpoint::post("/v1/chat-messages")),
            EndpointKind::SystemConfig => Some(Endpoint::get("/console/api/setup")),
            EndpointKind::SystemVersion => Some(Endpoint::get("/console/api/version")),
            EndpointKind::SystemHealth => Some(Endpoint::get("/console/api/ping")),
            EndpointKind::AuthLogin => Some(Endpoint::post("/console/api/login")),
            EndpointKind::FileUpload => Some(Endpoint::post("/console/api/files/upload")),
            EndpointKind::DatasetList => Some(Endpoint::get("/console/api/datasets")),
            EndpointKind::WorkflowRun => Some(Endpoint::post("/v1/workflows/run")),
            EndpointKind::PluginMarket => Some(Endpoint::get("/console/api/workspaces/current/plugin")),
            EndpointKind::McpServer => Some(Endpoint::get("/console/api/mcp")),
            _ => None,
        }
    }

    fn fingerprint_markers(&self) -> FingerprintSpec {
        FingerprintSpec {
            body_keywords: vec!["Dify", "dify-ai", "dify.ai"],
            header_markers: vec![("server", "werkzeug"), ("x-version", "")],
            probe_endpoints: vec![
                ProbeEndpoint {
                    path: "/console/api/setup",
                    method: "GET",
                    accept_statuses: vec![200, 401],
                    body_contains: None,
                },
            ],
        }
    }

    fn default_ports(&self) -> &[u16] { &[5001, 3000, 80, 443] }
}
