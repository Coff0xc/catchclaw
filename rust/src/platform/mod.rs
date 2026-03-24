pub mod profiles;
pub mod registry;

use std::fmt;
use std::str::FromStr;

/// Supported target platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetPlatform {
    OpenClaw,
    LibreChat,
    LobeChat,
    Dify,
    FastGPT,
    NextChat,
    AnythingLLM,
    Flowise,
    RagFlow,
    Unknown,
}

impl Default for TargetPlatform {
    fn default() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for TargetPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenClaw => write!(f, "OpenClaw"),
            Self::LibreChat => write!(f, "LibreChat"),
            Self::LobeChat => write!(f, "LobeChat"),
            Self::Dify => write!(f, "Dify"),
            Self::FastGPT => write!(f, "FastGPT"),
            Self::NextChat => write!(f, "NextChat"),
            Self::AnythingLLM => write!(f, "AnythingLLM"),
            Self::Flowise => write!(f, "Flowise"),
            Self::RagFlow => write!(f, "RagFlow"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl FromStr for TargetPlatform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "openclaw" | "open-webui" | "openwebui" => Ok(Self::OpenClaw),
            "librechat" => Ok(Self::LibreChat),
            "lobechat" => Ok(Self::LobeChat),
            "dify" => Ok(Self::Dify),
            "fastgpt" => Ok(Self::FastGPT),
            "nextchat" | "chatgpt-next-web" => Ok(Self::NextChat),
            "anythingllm" => Ok(Self::AnythingLLM),
            "flowise" => Ok(Self::Flowise),
            "ragflow" => Ok(Self::RagFlow),
            "unknown" | "auto" => Ok(Self::Unknown),
            _ => Err(format!("unknown platform: {s}")),
        }
    }
}

/// Capability flags for a platform
#[derive(Debug, Clone, Default)]
pub struct PlatformCapabilities {
    pub has_chat_completion: bool,
    pub has_websocket: bool,
    pub has_file_upload: bool,
    pub has_admin_panel: bool,
    pub has_plugin_system: bool,
    pub has_workflow_engine: bool,
    pub has_rag_pipeline: bool,
    pub has_oauth: bool,
    pub has_webhook: bool,
    pub has_audio: bool,
    pub has_mcp: bool,
}

/// Semantic endpoint category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    AuthLogin,
    AuthRegister,
    AuthToken,
    AuthConfig,

    ChatCompletion,
    ChatMessages,
    StreamingChat,

    SystemConfig,
    SystemVersion,
    SystemHealth,
    AdminPanel,

    FileUpload,
    FileList,
    FileDownload,

    ToolList,
    ToolInvoke,
    PluginMarket,
    SkillList,
    McpServer,

    WorkflowRun,
    WorkflowList,

    DatasetList,
    DatasetCreate,
    DocumentUpload,
    SearchQuery,

    WebhookEndpoint,
    WebSocketGateway,

    AudioSpeech,
    AudioTranscription,

    UserList,
    UserProfile,

    ConversationList,
    ConversationExport,

    OAuthCallback,
    OAuthAuthorize,
}

/// HTTP method (avoids reqwest dependency in this module)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GET => write!(f, "GET"),
            Self::POST => write!(f, "POST"),
            Self::PUT => write!(f, "PUT"),
            Self::DELETE => write!(f, "DELETE"),
            Self::PATCH => write!(f, "PATCH"),
        }
    }
}

/// A resolved endpoint with method and path
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub path: String,
    pub method: HttpMethod,
    pub fallbacks: Vec<String>,
}

impl Endpoint {
    pub fn get(path: impl Into<String>) -> Self {
        Self { path: path.into(), method: HttpMethod::GET, fallbacks: vec![] }
    }

    pub fn post(path: impl Into<String>) -> Self {
        Self { path: path.into(), method: HttpMethod::POST, fallbacks: vec![] }
    }

    pub fn with_fallback(mut self, path: impl Into<String>) -> Self {
        self.fallbacks.push(path.into());
        self
    }
}

/// Trait defining a platform's API surface
pub trait PlatformProfile: Send + Sync {
    fn platform(&self) -> TargetPlatform;
    fn name(&self) -> &str;
    fn capabilities(&self) -> PlatformCapabilities;
    fn resolve(&self, kind: EndpointKind) -> Option<Endpoint>;
    fn fingerprint_markers(&self) -> FingerprintSpec;
    fn default_ports(&self) -> &[u16];
    fn ws_protocol(&self) -> Option<WsProtocol> { None }
}

/// Fingerprint specification for platform detection
#[derive(Debug, Clone)]
pub struct FingerprintSpec {
    pub body_keywords: Vec<&'static str>,
    pub header_markers: Vec<(&'static str, &'static str)>,
    pub probe_endpoints: Vec<ProbeEndpoint>,
}

/// A probe endpoint for fingerprinting
#[derive(Debug, Clone)]
pub struct ProbeEndpoint {
    pub path: &'static str,
    pub method: &'static str,
    pub accept_statuses: Vec<u16>,
    pub body_contains: Option<&'static str>,
}

/// WebSocket protocol variant
#[derive(Debug, Clone, Copy)]
pub enum WsProtocol {
    OpenClawGateway,
    Standard,
    SocketIO,
}
