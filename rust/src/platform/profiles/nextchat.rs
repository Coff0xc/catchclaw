use crate::platform::*;

pub struct NextChatProfile;

impl PlatformProfile for NextChatProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::NextChat }
    fn name(&self) -> &str { "NextChat / ChatGPT-Next-Web" }

    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            has_chat_completion: true,
            has_websocket: false,
            has_file_upload: false,
            has_admin_panel: false,
            has_plugin_system: false,
            has_workflow_engine: false,
            has_rag_pipeline: false,
            has_oauth: false,
            has_webhook: false,
            has_audio: false,
            has_mcp: false,
        }
    }

    fn resolve(&self, kind: EndpointKind) -> Option<Endpoint> {
        match kind {
            EndpointKind::ChatCompletion => Some(Endpoint::post("/api/openai/v1/chat/completions")),
            EndpointKind::SystemConfig => Some(Endpoint::get("/api/config")),
            _ => None,
        }
    }

    fn fingerprint_markers(&self) -> FingerprintSpec {
        FingerprintSpec {
            body_keywords: vec!["NextChat", "ChatGPT Next Web", "chatgpt-next-web"],
            header_markers: vec![],
            probe_endpoints: vec![
                ProbeEndpoint {
                    path: "/api/config",
                    method: "GET",
                    accept_statuses: vec![200],
                    body_contains: Some("needCode"),
                },
            ],
        }
    }

    fn default_ports(&self) -> &[u16] { &[3000, 80, 443] }
}
