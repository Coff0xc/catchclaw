# Platform Abstraction Layer Design

> CatchClaw v6.0 — Multi-Platform Security Assessment Architecture
> Date: 2026-03-24

---

## 1. Current State Analysis

### 1.1 Hardcoded API Path Inventory

Extracted from 72 exploit modules in `rust/src/exploit/`. All paths are OpenClaw-specific:

**OpenClaw Core API (`/api/v1/...`)**
| Path | Used By |
|------|---------|
| `/api/v1/auths/` | `cors_bypass`, `guest_mode_abuse`, `localhost_trust`, `mdns_leak` |
| `/api/v1/configs/` | `env_inject` (×3), `guest_mode_abuse`, `localhost_trust`, `mdns_leak` |
| `/api/v1/users/` | `cors_bypass`, `localhost_trust` |
| `/api/v1/tools/` | `skill_supply_chain` |
| `/api/v1/tools/invoke` | `guest_mode_abuse` |
| `/api/v1/skills/` | `guest_mode_abuse`, `skill_supply_chain` |
| `/api/v1/files/attachments` | `ipv6_ssrf_bypass` |
| `/api/v1/audio/speech` | `voice_ext_rce` (×2) |
| `/api/v1/audio/transcriptions` | `voice_ext_rce` (×2) |
| `/api/v1/voice/config` | `voice_ext_rce` |
| `/api/v1/webhook/telegram` | `msg_platform_spoof` (×2) |
| `/api/v1/webhook/discord` | `msg_platform_spoof` |
| `/api/v1/webhook/matrix` | `msg_platform_spoof` |
| `/api/v1/webhook/bluebubbles` | `msg_platform_spoof` |

**OpenClaw General API**
| Path | Used By |
|------|---------|
| `/api/config` | `csrf_no_origin`, `mdns_leak` |
| `/api/chat/completions` | `cors_bypass`, `csrf_no_origin`, `env_inject`, `guest_mode_abuse`, `ipv6_ssrf_bypass`, `localhost_trust` |
| `/api/pipelines/run` | `ssrf` (×4) |
| `/api/share/create` | `link_template_inject` |
| `/api/export/markdown` | `link_template_inject` |
| `/api/conversations` | `transcript_theft` |
| `/api/history` | `transcript_theft` |
| `/api/webhooks` | `webhook_verify` |
| `/api/nodes/register` | `rogue_node` |
| `/api/pair` | `pairing_brute`, `silent_pair_abuse` |
| `/api/status` | `auth_mode_abuse`, `origin_wildcard` |
| `/api/version` | `auth_mode_abuse`, `mdns_leak` |
| `/api/memory/config` | `qmd_cmd_inject` |
| `/api/channels/discord/webhook` | `channel_inject` |
| `/api/channels/slack/oauth` | `oauth_abuse` |
| `/api/slack/oauth` | `oauth_abuse` |
| `/api/discord/interactions` | `channel_inject` |

**OpenClaw Internal / Gateway (`/__openclaw/...`)**
| Path | Used By |
|------|---------|
| `/__openclaw/api/config` | `qmd_cmd_inject` |
| `/__openclaw/api/pair` | `silent_pair_abuse` |
| `/__openclaw/api/nodes/register` | `rogue_node` |
| `/__openclaw/api/webhooks` | `webhook_verify` |
| `/__openclaw/api/transcripts` | `transcript_theft` |
| `/__openclaw/api/exec/approvals` | (exec modules) |
| `/__openclaw/api/exec/socket` | (exec modules) |
| `/__openclaw/api/exec/status` | (exec modules) |
| `/__openclaw/api/internal/config` | (internal) |
| `/__openclaw__/api/...` | (variant paths for same endpoints) |

**OpenAI-Compatible Endpoints**
| Path | Used By |
|------|---------|
| `/v1/chat/completions` | `cors_bypass`, `csrf_no_origin`, `origin_wildcard`, `ratelimit_scope_bypass` |
| `/v1/completions` | `ratelimit_scope_bypass` |
| `/v1/responses` | `ratelimit_scope_bypass` |

**WebSocket**
- All WS-based modules (30+) use `target.ws_url()` → `ws(s)://{host}:{port}` with OpenClaw Gateway protocol (`GatewayWsClient`)

**Health / Auth / OAuth**
| Path | Used By |
|------|---------|
| `/health` | `mdns_leak`, discovery |
| `/healthz` | `auth_mode_abuse`, `origin_wildcard` |
| `/api/internal/health` | `hidden_content` |
| `/auth` | `gateway_hijack` (UI path) |
| `/oauth/callback` | `oauth_token_theft` |
| `/auth/callback` | `oauth_token_theft` |
| `/api/auth/token` | `oauth_token_theft` |
| `/api/auth/pair` | `silent_pair_abuse` |

**LibreChat-Specific** (in `librechat_probe.rs`)
| Path | Purpose |
|------|---------|
| `/api/actions` | CVE-2025-69222 SSRF |
| `/api/files` | CVE-2025-69220 file access bypass |
| `/api/search/test` | CVE-2025-54868 chat exposure |
| `/api/auth/register` | User enumeration |

**LobeChat-Specific** (in `lobechat_probe.rs`)
| Path | Purpose |
|------|---------|
| `/api/chat` | CVE-2026-23733 XSS |
| `/api/plugins/market` | Plugin enumeration |
| `/trpc` | tRPC endpoint exposure |
| `/api/user` | User info leak |

### 1.2 Module Classification by Platform Dependency

**Category A: Deeply OpenClaw-Specific** (41 modules) — Use OpenClaw Gateway WS protocol, `/__openclaw/` paths, or OpenClaw-specific features (skills, pairing, exec approvals):
`acp_bypass`, `agent_file_inject`, `agent_inject`, `apikey_steal`, `approval_hijack`, `auth_disable_leak`, `auth_mode_abuse`, `browser_request`, `browser_upload_traversal`, `bypass_soul`, `c2_exfil`, `channel_inject`, `config_tamper`, `cron_bypass`, `env_inject`, `eval_inject`, `exec_race_toctou`, `exec_socket_leak`, `flood_guard_reset`, `gateway_hijack`, `guest_mode_abuse`, `hidden_content`, `hook_inject`, `keychain_cmd_inject`, `localhost_trust`, `mdns_leak`, `memory_data_leak`, `mcp_inject`, `pairing_brute`, `patch_escape`, `qmd_cmd_inject`, `rogue_node`, `secret_exec_abuse`, `secret_extract`, `secrets_resolve`, `session_file_write`, `session_hijack`, `silent_pair_abuse`, `skill_poison`, `skill_scanner_bypass`, `skill_supply_chain`

**Category B: Partially Portable** (17 modules) — Use common patterns (chat completions, CORS, SSRF, auth) that map across platforms with endpoint translation:
`cors_bypass`, `csrf_no_origin`, `ipv6_ssrf_bypass`, `link_template_inject`, `log_disclosure`, `marker_spoof`, `msg_platform_spoof`, `oauth_abuse`, `oauth_token_theft`, `obfuscation_bypass`, `origin_wildcard`, `prompt_inject`, `ratelimit_scope_bypass`, `rce`, `responses_exploit`, `ssrf`, `ssrf_proxy_bypass`, `ssrf_rebind`, `talk_secrets`, `tools_invoke`, `transcript_theft`, `unicode_bypass`, `voice_ext_rce`, `webhook_verify`, `ws_auth_brute`, `ws_fuzz`, `ws_hijack`, `redact_bypass`

**Category C: Already Platform-Specific Probes** (2 modules):
`librechat_probe`, `lobechat_probe`

**Category D: Fully Generic** (2 modules — no platform-specific paths):
`obfuscation_bypass` (payload encoding test), `unicode_bypass` (WAF bypass)

---

## 2. Platform Profile Design

### 2.1 Core Types

```rust
// rust/src/platform/mod.rs

use std::collections::HashMap;

/// Supported target platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetPlatform {
    OpenClaw,      // Open-WebUI / OpenClaw Gateway
    LibreChat,     // LibreChat
    LobeChat,      // LobeChat
    Dify,          // Dify
    FastGPT,       // FastGPT
    NextChat,      // ChatGPT-Next-Web / NextChat
    AnythingLLM,   // AnythingLLM
    Flowise,       // Flowise
    RagFlow,       // RagFlow
    Unknown,       // Not yet identified
}

/// Capability flags — what the platform supports
#[derive(Debug, Clone, Default)]
pub struct PlatformCapabilities {
    pub has_chat_completion: bool,   // OpenAI-compatible chat endpoint
    pub has_websocket: bool,         // Real-time WS communication
    pub has_file_upload: bool,       // File/attachment upload
    pub has_admin_panel: bool,       // Admin/system management
    pub has_plugin_system: bool,     // Plugin/tool/MCP marketplace
    pub has_workflow_engine: bool,   // Visual workflow / DAG execution
    pub has_rag_pipeline: bool,      // Knowledge base / dataset
    pub has_oauth: bool,             // OAuth integration
    pub has_webhook: bool,           // Webhook endpoints
    pub has_audio: bool,             // Speech/transcription
    pub has_mcp: bool,               // MCP protocol support
}

/// Semantic endpoint category — platform-agnostic function
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    // Auth
    AuthLogin,
    AuthRegister,
    AuthToken,
    AuthConfig,

    // Chat / Inference
    ChatCompletion,     // OpenAI-compatible
    ChatMessages,       // Platform-native chat
    StreamingChat,

    // Config / System
    SystemConfig,
    SystemVersion,
    SystemHealth,
    AdminPanel,

    // Files
    FileUpload,
    FileList,
    FileDownload,

    // Tools / Plugins / Skills
    ToolList,
    ToolInvoke,
    PluginMarket,
    SkillList,
    McpServer,

    // Workflow
    WorkflowRun,
    WorkflowList,

    // RAG / Knowledge
    DatasetList,
    DatasetCreate,
    DocumentUpload,
    SearchQuery,

    // Communication
    WebhookEndpoint,
    WebSocketGateway,

    // Audio
    AudioSpeech,
    AudioTranscription,

    // User
    UserList,
    UserProfile,

    // Conversations
    ConversationList,
    ConversationExport,

    // OAuth
    OAuthCallback,
    OAuthAuthorize,

    // Platform-specific (extensible)
    Custom(&'static str),
}

/// A resolved endpoint with method and path
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub path: String,
    pub method: reqwest::Method,
    /// Alternative paths to try (e.g., `/__openclaw/api/config` fallback)
    pub fallbacks: Vec<String>,
}

impl Endpoint {
    pub fn get(path: impl Into<String>) -> Self {
        Self { path: path.into(), method: reqwest::Method::GET, fallbacks: vec![] }
    }
    pub fn post(path: impl Into<String>) -> Self {
        Self { path: path.into(), method: reqwest::Method::POST, fallbacks: vec![] }
    }
    pub fn with_fallback(mut self, path: impl Into<String>) -> Self {
        self.fallbacks.push(path.into());
        self
    }
}
```

### 2.2 PlatformProfile Trait

```rust
/// Trait defining a platform's API surface
pub trait PlatformProfile: Send + Sync {
    /// Platform identity
    fn platform(&self) -> TargetPlatform;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Capability flags
    fn capabilities(&self) -> &PlatformCapabilities;

    /// Resolve a semantic endpoint to a concrete path.
    /// Returns None if the platform doesn't support this endpoint.
    fn resolve(&self, kind: EndpointKind) -> Option<Endpoint>;

    /// Fingerprint markers for detection
    fn fingerprint_markers(&self) -> FingerprintSpec;

    /// Default ports
    fn default_ports(&self) -> &[u16];

    /// WebSocket protocol handler (if supported)
    fn ws_protocol(&self) -> Option<WsProtocol> { None }
}

/// Fingerprint specification for platform detection
#[derive(Debug, Clone)]
pub struct FingerprintSpec {
    /// HTML body keywords (case-insensitive)
    pub body_keywords: Vec<&'static str>,
    /// HTTP header checks (header_name, substring_match)
    pub header_markers: Vec<(&'static str, &'static str)>,
    /// Probe endpoints that confirm identity
    pub probe_endpoints: Vec<ProbeEndpoint>,
}

#[derive(Debug, Clone)]
pub struct ProbeEndpoint {
    pub path: &'static str,
    pub method: &'static str,
    /// Expected: 200/401/403 are all "endpoint exists"
    pub accept_statuses: Vec<u16>,
    /// Optional body keyword to confirm
    pub body_contains: Option<&'static str>,
}

/// WebSocket protocol variant
#[derive(Debug, Clone, Copy)]
pub enum WsProtocol {
    /// OpenClaw Gateway WS with challenge handshake
    OpenClawGateway,
    /// Standard WebSocket (JSON messages)
    Standard,
    /// Socket.IO based
    SocketIO,
}
```

### 2.3 OpenClaw Profile Implementation (Reference)

```rust
pub struct OpenClawProfile;

impl PlatformProfile for OpenClawProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::OpenClaw }
    fn name(&self) -> &str { "OpenClaw / Open-WebUI" }

    fn capabilities(&self) -> &PlatformCapabilities {
        &PlatformCapabilities {
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
            EndpointKind::UserList => Some(Endpoint::get("/api/v1/users/")),
            EndpointKind::SystemHealth => Some(
                Endpoint::get("/health").with_fallback("/healthz")
            ),
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
            EndpointKind::AuthConfig => Some(Endpoint::get("/api/v1/configs/")),
            EndpointKind::SystemVersion => Some(Endpoint::get("/api/version")),
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
```

### 2.4 Dify Profile Example

```rust
pub struct DifyProfile;

impl PlatformProfile for DifyProfile {
    fn platform(&self) -> TargetPlatform { TargetPlatform::Dify }
    fn name(&self) -> &str { "Dify" }

    fn capabilities(&self) -> &PlatformCapabilities {
        &PlatformCapabilities {
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
```

---

## 3. API Mapping Mechanism

### 3.1 PlatformRegistry

```rust
// rust/src/platform/registry.rs

use std::sync::OnceLock;

static REGISTRY: OnceLock<PlatformRegistry> = OnceLock::new();

pub struct PlatformRegistry {
    profiles: Vec<Box<dyn PlatformProfile>>,
}

impl PlatformRegistry {
    pub fn global() -> &'static Self {
        REGISTRY.get_or_init(|| Self {
            profiles: vec![
                Box::new(OpenClawProfile),
                Box::new(LibreChatProfile),
                Box::new(LobeChatProfile),
                Box::new(DifyProfile),
                Box::new(FastGPTProfile),
                Box::new(NextChatProfile),
                Box::new(AnythingLLMProfile),
                Box::new(FlowiseProfile),
                Box::new(RagFlowProfile),
            ],
        })
    }

    /// Get profile by platform enum
    pub fn get(&self, platform: TargetPlatform) -> Option<&dyn PlatformProfile> {
        self.profiles.iter()
            .find(|p| p.platform() == platform)
            .map(|p| p.as_ref())
    }

    /// Get all profiles for fingerprinting
    pub fn all(&self) -> &[Box<dyn PlatformProfile>] {
        &self.profiles
    }
}
```

### 3.2 Integration with ExploitCtx

```rust
// Changes to ExploitCtx in base.rs

pub struct ExploitCtx {
    // ... existing fields ...
    pub platform: TargetPlatform,
    profile: &'static dyn PlatformProfile,
}

impl ExploitCtx {
    /// Resolve an endpoint for the current platform.
    /// Returns full URL (base_url + path).
    pub fn endpoint(&self, kind: EndpointKind) -> Option<String> {
        self.profile.resolve(kind)
            .map(|ep| format!("{}{}", self.base_url, ep.path))
    }

    /// Resolve endpoint with fallback URLs
    pub fn endpoint_with_fallbacks(&self, kind: EndpointKind) -> Vec<String> {
        match self.profile.resolve(kind) {
            Some(ep) => {
                let mut urls = vec![format!("{}{}", self.base_url, ep.path)];
                for fb in &ep.fallbacks {
                    urls.push(format!("{}{}", self.base_url, fb));
                }
                urls
            }
            None => vec![],
        }
    }

    /// Check if platform supports a given capability
    pub fn has_capability(&self, check: impl Fn(&PlatformCapabilities) -> bool) -> bool {
        check(self.profile.capabilities())
    }
}
```

### 3.3 Exploit Module Migration Pattern

**Before** (hardcoded):
```rust
let url = format!("{}/api/chat/completions", ctx.base_url);
```

**After** (abstracted):
```rust
let Some(url) = ctx.endpoint(EndpointKind::ChatCompletion) else {
    ctx.log_clean("module_name");
    return findings;
};
```

For modules that probe multiple fallback paths:
```rust
for url in ctx.endpoint_with_fallbacks(EndpointKind::SystemConfig) {
    if let Ok(resp) = ctx.client.get(&url).send().await { ... }
}
```

---

## 4. Discovery / Fingerprinting Changes

### 4.1 Extended `fingerprint` Function

Replace `fingerprint_openclaw` with a generic multi-platform fingerprinter:

```rust
// rust/src/utils/discovery.rs

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub host: String,
    pub port: u16,
    pub platform: TargetPlatform,  // was: is_openclaw: bool
    pub version: Option<String>,
    pub features: Vec<String>,
    pub confidence: f32,           // 0.0 - 1.0
}

/// Detect which AI platform is running on host:port
pub async fn fingerprint_service(
    host: &str, port: u16, tls: bool, dur: Duration
) -> ServiceInfo {
    let scheme = if tls { "https" } else { "http" };
    let base = format!("{scheme}://{host}:{port}");
    let client = crate::utils::build_client(dur);

    let registry = PlatformRegistry::global();
    let mut best_match = TargetPlatform::Unknown;
    let mut best_score: f32 = 0.0;
    let mut version = None;
    let mut features = Vec::new();

    // Fetch index page once
    let index_body = client.get(&base).send().await
        .ok()
        .and_then(|r| {
            // Check headers against all profiles
            for profile in registry.all() {
                let spec = profile.fingerprint_markers();
                for (hdr, val) in &spec.header_markers {
                    if let Some(hv) = r.headers().get(*hdr) {
                        if let Ok(s) = hv.to_str() {
                            if val.is_empty() || s.to_lowercase().contains(val) {
                                // score boost
                            }
                        }
                    }
                }
            }
            // Can't re-use response after .text(), so handle in closure
            futures::executor::block_on(r.text()).ok()
        });

    // Match body keywords
    if let Some(ref body) = index_body {
        for profile in registry.all() {
            let spec = profile.fingerprint_markers();
            let mut score: f32 = 0.0;
            for kw in &spec.body_keywords {
                if body.contains(kw) {
                    score += 0.3;
                }
            }
            if score > best_score {
                best_score = score;
                best_match = profile.platform();
            }
        }
    }

    // Probe characteristic endpoints for top candidates
    for profile in registry.all() {
        let spec = profile.fingerprint_markers();
        for probe in &spec.probe_endpoints {
            let url = format!("{base}{}", probe.path);
            if let Ok(resp) = client.get(&url).send().await {
                let status = resp.status().as_u16();
                if probe.accept_statuses.contains(&status) {
                    // Confirmed
                    best_match = profile.platform();
                    best_score = 0.9;
                    features.push(probe.path.to_string());
                }
            }
        }
    }

    ServiceInfo {
        host: host.to_string(),
        port,
        platform: best_match,
        version,
        features,
        confidence: best_score,
    }
}
```

### 4.2 Target Struct Extension

```rust
// Extend Target in utils/types.rs
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub platform: TargetPlatform,  // NEW: detected or user-specified
}
```

CLI flag: `--platform openclaw|librechat|lobechat|dify|fastgpt|nextchat|anythingllm|flowise|ragflow|auto`

Default: `auto` (fingerprint-based detection).

---

## 5. Impact Assessment

### 5.1 Modules Requiring Changes

| Impact Level | Count | Modules | Change Needed |
|-------------|-------|---------|---------------|
| **No change** | 2 | `obfuscation_bypass`, `unicode_bypass` | Fully generic, no API paths |
| **No change** | 2 | `librechat_probe`, `lobechat_probe` | Already platform-specific |
| **Low** (path substitution only) | 17 | Category B modules | Replace hardcoded paths with `ctx.endpoint()` |
| **Medium** (path + logic) | 10 | `ssrf`, `cors_bypass`, `csrf_no_origin`, `prompt_inject`, `ratelimit_scope_bypass`, `oauth_abuse`, `oauth_token_theft`, `voice_ext_rce`, `msg_platform_spoof`, `transcript_theft` | Path abstraction + conditional logic per platform |
| **High** (OpenClaw-only) | 41 | Category A modules | Keep as-is, gate with `if ctx.platform == OpenClaw` |

### 5.2 Files to Create

| File | Purpose |
|------|---------|
| `rust/src/platform/mod.rs` | Core types: `TargetPlatform`, `EndpointKind`, `PlatformProfile` trait, `PlatformCapabilities` |
| `rust/src/platform/registry.rs` | `PlatformRegistry` singleton, profile registration |
| `rust/src/platform/profiles/mod.rs` | Profile submodule |
| `rust/src/platform/profiles/openclaw.rs` | OpenClaw endpoint mapping |
| `rust/src/platform/profiles/librechat.rs` | LibreChat endpoint mapping |
| `rust/src/platform/profiles/lobechat.rs` | LobeChat endpoint mapping |
| `rust/src/platform/profiles/dify.rs` | Dify endpoint mapping |
| `rust/src/platform/profiles/fastgpt.rs` | FastGPT endpoint mapping |
| `rust/src/platform/profiles/nextchat.rs` | NextChat endpoint mapping |
| `rust/src/platform/profiles/anythingllm.rs` | AnythingLLM endpoint mapping |
| `rust/src/platform/profiles/flowise.rs` | Flowise endpoint mapping |
| `rust/src/platform/profiles/ragflow.rs` | RagFlow endpoint mapping |

### 5.3 Files to Modify

| File | Change |
|------|--------|
| `rust/src/main.rs` | Add `--platform` CLI flag, `mod platform` |
| `rust/src/utils/types.rs` | Add `platform: TargetPlatform` to `Target` |
| `rust/src/utils/discovery.rs` | Replace `fingerprint_openclaw` with `fingerprint_service` |
| `rust/src/exploit/base.rs` | Add `platform` + `profile` to `ExploitCtx`, add `endpoint()` method |
| `rust/src/scan/mod.rs` | Pass platform info through scan pipeline |
| 17 Category B exploit modules | Replace hardcoded paths with `ctx.endpoint()` |

### 5.4 Migration Strategy

**Phase 1**: Add `platform/` module with types + OpenClaw profile. Wire into `ExploitCtx`. No exploit changes yet — backward compatible.

**Phase 2**: Migrate Category B modules (17) to use `ctx.endpoint()`. Gate Category A modules (41) with platform check.

**Phase 3**: Add remaining 8 platform profiles. Extend discovery fingerprinting.

**Phase 4**: Create platform-specific probe modules (like existing `librechat_probe` / `lobechat_probe`) for Dify, FastGPT, NextChat, AnythingLLM, Flowise, RagFlow.

---

## 6. Cross-Platform Endpoint Mapping Matrix

| EndpointKind | OpenClaw | LibreChat | LobeChat | Dify | FastGPT | NextChat | AnythingLLM | Flowise | RagFlow |
|-------------|----------|-----------|----------|------|---------|----------|-------------|---------|---------|
| ChatCompletion | `/api/chat/completions` | `/api/ask/{model}` | `/api/chat` | `/v1/chat-messages` | `/api/v1/chat/completions` | `/api/openai/v1/chat/completions` | `/api/v1/workspace/{slug}/chat` | `/api/v1/prediction/{id}` | `/v1/api/chat/completions` |
| SystemConfig | `/api/config` | — | — | `/console/api/setup` | `/api/system/getInitData` | `/api/config` | `/api/v1/system/env` | `/api/v1/settings` | — |
| SystemHealth | `/health` | — | — | `/console/api/ping` | — | — | `/api/ping` | `/api/v1/ping` | — |
| AuthLogin | `/api/v1/auths/` | `/api/auth/login` | — | `/console/api/login` | `/api/support/user/account/login` | — (CODE env) | `/api/v1/auth` | — | `/api/auth/login` |
| FileUpload | `/api/v1/files/attachments` | `/api/files` | — | `/console/api/files/upload` | `/api/core/dataset/collection/create/localFile` | — | `/api/v1/document/upload` | `/api/v1/attachments` | `/api/document/upload` |
| ToolInvoke | `/api/v1/tools/invoke` | — | — | — | — | — | — | — | — |
| WorkflowRun | `/api/pipelines/run` | — | — | `/v1/workflows/run` | `/api/core/workflow/run` | — | — | `/api/v1/agentflowv2-generator` | `/api/canvas/run` |
| DatasetList | — | — | — | `/console/api/datasets` | `/api/core/dataset/list` | — | `/api/v1/documents` | `/api/v1/datasets` | `/api/kb/list` |
| PluginMarket | — | — | `/api/plugins/market` | `/console/api/workspaces/current/plugin` | `/api/marketplace/list` | — | `/api/v1/extensions` | `/api/v1/marketplaces` | `/api/plugin/list` |

---

## 7. Design Decisions

1. **Trait-based, not config-based**: Profiles are compiled-in Rust types, not runtime TOML/YAML. This ensures type safety and allows the compiler to catch missing mappings. Endpoint YAML mapping was considered but rejected — the mapping logic often needs method + fallbacks + conditions that YAML handles poorly.

2. **`EndpointKind` enum over string keys**: Compile-time exhaustive matching prevents typos and missing mappings. New endpoints require explicit enum variant addition.

3. **Fallback paths**: OpenClaw has `/__openclaw/` prefix variants. Other platforms may have similar path aliases. The `Endpoint::fallbacks` field handles this without complicating exploit module code.

4. **Capability gating**: Exploit modules can check `ctx.has_capability(|c| c.has_workflow_engine)` to skip irrelevant tests early, avoiding noise and false positives.

5. **Category A modules stay OpenClaw-only**: 41 modules deeply depend on OpenClaw Gateway protocol (WS challenge handshake, exec approvals, skill system). Abstracting these would require implementing equivalent protocol handlers for each platform — not worth it. Instead, gate them with `if ctx.platform != OpenClaw { return }`.

6. **Confidence scoring in fingerprinting**: Multiple platforms share port 3000. Confidence scoring with multi-signal detection (body keywords + headers + probe endpoints) disambiguates correctly.
