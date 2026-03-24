use crate::platform::*;

pub struct LibreChatProfile;

impl PlatformProfile for LibreChatProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::LibreChat }
    fn name(&self) -> &str { "LibreChat" }

    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            has_chat_completion: true,
            has_websocket: false,
            has_file_upload: true,
            has_admin_panel: true,
            has_plugin_system: true,
            has_workflow_engine: false,
            has_rag_pipeline: true,
            has_oauth: true,
            has_webhook: false,
            has_audio: false,
            has_mcp: true,
        }
    }

    fn resolve(&self, kind: EndpointKind) -> Option<Endpoint> {
        match kind {
            EndpointKind::ChatCompletion => Some(Endpoint::post("/api/ask/openAI")),
            EndpointKind::AuthLogin => Some(Endpoint::post("/api/auth/login")),
            EndpointKind::AuthRegister => Some(Endpoint::post("/api/auth/register")),
            EndpointKind::FileUpload => Some(Endpoint::post("/api/files")),
            EndpointKind::FileList => Some(Endpoint::get("/api/files")),
            EndpointKind::SearchQuery => Some(Endpoint::get("/api/search/test")),
            EndpointKind::PluginMarket => Some(Endpoint::get("/api/plugins")),
            EndpointKind::ToolList => Some(Endpoint::get("/api/actions")),
            EndpointKind::ConversationList => Some(Endpoint::get("/api/convos")),
            EndpointKind::UserProfile => Some(Endpoint::get("/api/user")),
            _ => None,
        }
    }

    fn fingerprint_markers(&self) -> FingerprintSpec {
        FingerprintSpec {
            body_keywords: vec!["LibreChat", "librechat"],
            header_markers: vec![],
            probe_endpoints: vec![
                ProbeEndpoint {
                    path: "/api/auth/login",
                    method: "GET",
                    accept_statuses: vec![200, 401, 404, 405],
                    body_contains: None,
                },
            ],
        }
    }

    fn default_ports(&self) -> &[u16] { &[3080, 3000, 80] }
}
