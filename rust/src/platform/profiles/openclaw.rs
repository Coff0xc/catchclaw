use crate::platform::*;

pub struct OpenClawProfile;

impl PlatformProfile for OpenClawProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::OpenClaw }
    fn name(&self) -> &str { "OpenClaw / Open-WebUI" }

    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            has_chat_completion: true,
            has_websocket: true,
            has_file_upload: true,
            has_admin_panel: true,
            has_plugin_system: true,
            has_workflow_engine: false,
            has_rag_pipeline: false,
            has_oauth: true,
            has_webhook: true,
            has_audio: true,
            has_mcp: true,
        }
    }

    fn resolve(&self, kind: EndpointKind) -> Option<Endpoint> {
        match kind {
            EndpointKind::ChatCompletion => Some(
                Endpoint::post("/api/chat/completions")
                    .with_fallback("/v1/chat/completions")
            ),
            EndpointKind::SystemConfig => Some(
                Endpoint::get("/api/config")
                    .with_fallback("/__openclaw/api/config")
            ),
            EndpointKind::AuthLogin => Some(Endpoint::get("/api/v1/auths/")),
            EndpointKind::AuthConfig => Some(Endpoint::get("/api/v1/configs/")),
            EndpointKind::UserList => Some(Endpoint::get("/api/v1/users/")),
            EndpointKind::SystemHealth => Some(
                Endpoint::get("/health").with_fallback("/healthz")
            ),
            EndpointKind::SystemVersion => Some(Endpoint::get("/api/version")),
            EndpointKind::FileUpload => Some(Endpoint::post("/api/v1/files/attachments")),
            EndpointKind::ToolList => Some(Endpoint::get("/api/v1/tools/")),
            EndpointKind::ToolInvoke => Some(Endpoint::post("/api/v1/tools/invoke")),
            EndpointKind::SkillList => Some(Endpoint::get("/api/v1/skills/")),
            EndpointKind::WebSocketGateway => Some(Endpoint::get("/ws")),
            EndpointKind::AudioSpeech => Some(Endpoint::post("/api/v1/audio/speech")),
            EndpointKind::AudioTranscription => Some(Endpoint::post("/api/v1/audio/transcriptions")),
            EndpointKind::ConversationList => Some(
                Endpoint::get("/api/conversations")
                    .with_fallback("/__openclaw/api/transcripts")
            ),
            EndpointKind::WebhookEndpoint => Some(
                Endpoint::get("/api/webhooks")
                    .with_fallback("/__openclaw/api/webhooks")
            ),
            EndpointKind::WorkflowRun => Some(Endpoint::post("/api/pipelines/run")),
            _ => None,
        }
    }

    fn fingerprint_markers(&self) -> FingerprintSpec {
        FingerprintSpec {
            body_keywords: vec!["open-webui", "Open WebUI", "openclaw"],
            header_markers: vec![("server", "open-webui"), ("server", "openclaw")],
            probe_endpoints: vec![
                ProbeEndpoint {
                    path: "/api/config",
                    method: "GET",
                    accept_statuses: vec![200],
                    body_contains: Some("name"),
                },
                ProbeEndpoint {
                    path: "/api/v1/auths/",
                    method: "GET",
                    accept_statuses: vec![200, 401, 403],
                    body_contains: None,
                },
            ],
        }
    }

    fn default_ports(&self) -> &[u16] { &[8080, 3000, 8000] }

    fn ws_protocol(&self) -> Option<WsProtocol> {
        Some(WsProtocol::OpenClawGateway)
    }
}
