use crate::platform::*;

pub struct LobeChatProfile;

impl PlatformProfile for LobeChatProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::LobeChat }
    fn name(&self) -> &str { "LobeChat" }

    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            has_chat_completion: true,
            has_websocket: false,
            has_file_upload: false,
            has_admin_panel: false,
            has_plugin_system: true,
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
            EndpointKind::ChatCompletion => Some(Endpoint::post("/api/chat")),
            EndpointKind::PluginMarket => Some(Endpoint::get("/api/plugins/market")),
            EndpointKind::UserProfile => Some(Endpoint::get("/api/user")),
            EndpointKind::SystemConfig => Some(Endpoint::get("/api/config")),
            _ => None,
        }
    }

    fn fingerprint_markers(&self) -> FingerprintSpec {
        FingerprintSpec {
            body_keywords: vec!["LobeChat", "lobechat", "lobehub"],
            header_markers: vec![],
            probe_endpoints: vec![
                ProbeEndpoint {
                    path: "/trpc",
                    method: "GET",
                    accept_statuses: vec![200, 404],
                    body_contains: None,
                },
            ],
        }
    }

    fn default_ports(&self) -> &[u16] { &[3210, 3000, 80] }
}
