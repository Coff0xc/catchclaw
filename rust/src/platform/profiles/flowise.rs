use crate::platform::*;

pub struct FlowiseProfile;

impl PlatformProfile for FlowiseProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::Flowise }
    fn name(&self) -> &str { "Flowise" }

    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            has_chat_completion: true,
            has_websocket: true,
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
            EndpointKind::ChatCompletion => Some(Endpoint::post("/api/v1/prediction/{id}")),
            EndpointKind::SystemConfig => Some(Endpoint::get("/api/v1/settings")),
            EndpointKind::SystemHealth => Some(Endpoint::get("/api/v1/ping")),
            EndpointKind::FileUpload => Some(Endpoint::post("/api/v1/attachments")),
            EndpointKind::DatasetList => Some(Endpoint::get("/api/v1/datasets")),
            EndpointKind::WorkflowRun => Some(Endpoint::post("/api/v1/agentflowv2-generator")),
            EndpointKind::PluginMarket => Some(Endpoint::get("/api/v1/marketplaces")),
            _ => None,
        }
    }

    fn fingerprint_markers(&self) -> FingerprintSpec {
        FingerprintSpec {
            body_keywords: vec!["Flowise", "flowise"],
            header_markers: vec![],
            probe_endpoints: vec![
                ProbeEndpoint {
                    path: "/api/v1/ping",
                    method: "GET",
                    accept_statuses: vec![200],
                    body_contains: None,
                },
            ],
        }
    }

    fn default_ports(&self) -> &[u16] { &[3000, 80, 443] }

    fn ws_protocol(&self) -> Option<WsProtocol> {
        Some(WsProtocol::SocketIO)
    }
}
