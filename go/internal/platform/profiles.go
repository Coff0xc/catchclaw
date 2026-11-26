package platform

import "github.com/Coff0xc/catchclaw/go/internal/core"

type baseProfile struct {
	platform     core.Platform
	name         string
	caps         Capabilities
	endpoints    map[EndpointKind]*Endpoint
	fingerprint  FingerprintSpec
	defaultPorts []int
}

func (b *baseProfile) Platform() core.Platform      { return b.platform }
func (b *baseProfile) Name() string                 { return b.name }
func (b *baseProfile) Capabilities() Capabilities   { return b.caps }
func (b *baseProfile) DefaultPorts() []int          { return b.defaultPorts }
func (b *baseProfile) Fingerprint() FingerprintSpec { return b.fingerprint }

func (b *baseProfile) Resolve(kind EndpointKind) *Endpoint {
	if ep, ok := b.endpoints[kind]; ok {
		return ep
	}
	return nil
}

func EP(path string, method HTTPMethod, fallbacks ...interface{}) *Endpoint {
	fb := make([]string, 0, len(fallbacks))
	for _, f := range fallbacks {
		if s, ok := f.(string); ok {
			fb = append(fb, s)
		}
	}
	return &Endpoint{Path: path, Method: method, Fallbacks: fb}
}

func NewOpenClawProfile() Profile {
	return &baseProfile{
		platform: core.PlatformOpenClaw,
		name:     "OpenClaw",
		caps: Capabilities{
			ChatCompletion: true, WebSocket: true, FileUpload: true,
			PluginSystem: true, OAuth: true, Webhook: true,
			Audio: true, MCP: true, SkillSystem: true, Sandbox: true,
		},
		defaultPorts: []int{8080, 3000, 8081, 11434},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:        EP("/api/auth/login", MethodPOST),
			EPAuthToken:        EP("/api/auth/token", MethodPOST),
			EPChatCompletion:   EP("/api/chat/completions", MethodPOST, "/v1/chat/completions", "/openai/chat/completions"),
			EPStreamingChat:    EP("/api/chat/stream", MethodPOST),
			EPSystemConfig:     EP("/api/config", MethodGET),
			EPSystemVersion:    EP("/api/version", MethodGET),
			EPSystemHealth:     EP("/api/health", MethodGET),
			EPAdminPanel:       EP("/admin", MethodGET, "/admin/", MethodGET),
			EPFileUpload:       EP("/api/files", MethodPOST),
			EPFileList:         EP("/api/files", MethodGET),
			EPToolList:         EP("/api/tools", MethodGET),
			EPToolInvoke:       EP("/api/tools/invoke", MethodPOST),
			EPPluginMarket:     EP("/api/plugins", MethodGET),
			EPSkillList:        EP("/api/skills", MethodGET),
			EPMcpServer:        EP("/api/mcp", MethodGET, "/mcp", MethodGET),
			EPWebSocketGateway: EP("/ws/gateway", MethodGET),
			EPWorkflowRun:      EP("/api/workflows/run", MethodPOST),
			EPWebhookEndpoint:  EP("/api/hooks", MethodPOST),
			EPUserList:         EP("/api/users", MethodGET),
			EPUserProfile:      EP("/api/profile", MethodGET),
			EPConversationList: EP("/api/conversations", MethodGET),
			EPOAuthCallback:    EP("/api/oauth/callback", MethodGET),
			EPOAuthAuthorize:   EP("/api/oauth/authorize", MethodGET),
			EPLogsQuery:        EP("/api/logs/query", MethodPOST),
			EPExecRun:          EP("/api/system/run", MethodPOST),
			EPExecApproval:     EP("/api/approvals", MethodGET, "/api/exec/approvals", MethodGET),
			EPConfigSet:        EP("/api/config/set", MethodPOST),
			EPConfigGet:        EP("/api/config/get", MethodGET),
			EPPairingCode:      EP("/api/pairing", MethodPOST),
			EPBrowserNavigate:  EP("/api/browser/navigate", MethodPOST),
			EPBrowserRequest:   EP("/api/browser/request", MethodPOST),
			EPAgentCreate:      EP("/api/agents/create", MethodPOST),
			EPAgentUpdate:      EP("/api/agents/update", MethodPOST),
			EPAgentFiles:       EP("/api/agents/files/set", MethodPOST),
			EPCronList:         EP("/api/cron/list", MethodGET),
			EPCronSet:          EP("/api/cron/set", MethodPOST),
			EPSkillScan:        EP("/api/skills/scan", MethodGET),
			EPUploadFile:       EP("/api/files/upload", MethodPOST),
			EPKnowledgeBase:    EP("/api/knowledge", MethodGET),
			EPModelConfig:      EP("/api/models/config", MethodGET),
			EPSandboxRun:       EP("/api/sandbox/run", MethodPOST),
			EPSessionList:      EP("/api/sessions", MethodGET),
			EPSessionPreview:   EP("/api/sessions/preview", MethodGET),
			EPSessionPatch:     EP("/api/sessions/patch", MethodPOST),
			EPTalkConfig:       EP("/api/talk/config", MethodGET),
			EPTalkSecrets:      EP("/api/talk/secrets", MethodGET),
			EPSecretList:       EP("/api/secrets/list", MethodGET),
			EPSecretGet:        EP("/api/secrets/get", MethodGET, "/api/secrets/resolve", MethodPOST),
			EPCredentialList:   EP("/api/credentials/list", MethodGET),
			EPCredentialStore:  EP("/api/credentials/store", MethodPOST),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords:  []string{"openclaw", "open-webui", "open webui", "ollama", "chat completions"},
			HeaderMarkers: map[string]string{"X-OpenClaw-Version": ""},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/version", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/api/config", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewDifyProfile() Profile {
	return &baseProfile{
		platform: core.PlatformDify,
		name:     "Dify",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: true, PluginSystem: true,
			WorkflowEngine: true, RAGPipeline: true, MultiTenant: true,
			Webhook: true, MCP: true, Sandbox: true,
		},
		defaultPorts: []int{80, 443, 3000, 8080},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:          EP("/console/api/login", MethodPOST),
			EPAuthRegister:       EP("/console/api/register", MethodPOST),
			EPAuthToken:          EP("/v1/passport", MethodGET),
			EPChatCompletion:     EP("/v1/chat-messages", MethodPOST),
			EPSystemConfig:       EP("/api/v1/system-config", MethodGET, "/console/api/setup", MethodGET),
			EPSystemVersion:      EP("/api/v1/version", MethodGET),
			EPSystemHealth:       EP("/health", MethodGET),
			EPAdminPanel:         EP("/admin", MethodGET, "/console", MethodGET),
			EPFileUpload:         EP("/v1/files/upload", MethodPOST),
			EPFileList:           EP("/v1/files", MethodGET),
			EPPluginMarket:       EP("/api/v1/plugins", MethodGET),
			EPSkillList:          EP("/api/v1/plugins", MethodGET),
			EPMcpServer:          EP("/mcp", MethodGET, "/api/v1/mcp", MethodGET),
			EPWorkflowRun:        EP("/v1/workflows/run", MethodPOST),
			EPWorkflowList:       EP("/api/v1/workflows", MethodGET),
			EPDatasetList:        EP("/v1/datasets", MethodGET),
			EPDatasetCreate:      EP("/v1/datasets", MethodPOST),
			EPDocumentUpload:     EP("/v1/datasets/{id}/document", MethodPOST),
			EPSearchQuery:        EP("/v1/datasets/{id}/retrieve", MethodPOST),
			EPWebhookEndpoint:    EP("/v1/webhooks", MethodPOST),
			EPUserList:           EP("/console/api/users", MethodGET),
			EPConversationList:   EP("/v1/conversations", MethodGET),
			EPConversationExport: EP("/v1/conversations/export", MethodGET),
			EPModelConfig:        EP("/console/api/workspaces/current/model-config", MethodGET),
			EPPluginDaemon:       EP("/plugin/daemon", MethodGET),
			EPSandboxRun:         EP("/v1/sandbox/run", MethodPOST),
			EPTenantSwitch:       EP("/console/api/workspaces/switch", MethodPOST),
			EPCredentialList:     EP("/api/v1/credentials", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords:  []string{"dify", "dify.ai"},
			HeaderMarkers: map[string]string{"X-Dify-Version": ""},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/v1/version", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/health", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewFastGPTProfile() Profile {
	return &baseProfile{
		platform: core.PlatformFastGPT,
		name:     "FastGPT",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: true, RAGPipeline: true,
			MultiTenant: true, Webhook: true,
		},
		defaultPorts: []int{3000, 8080},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:        EP("/api/proApi/user/login", MethodPOST),
			EPChatCompletion:   EP("/api/v1/chat/completions", MethodPOST),
			EPSystemVersion:    EP("/api/version", MethodGET),
			EPSystemHealth:     EP("/healthz", MethodGET),
			EPAdminPanel:       EP("/admin", MethodGET),
			EPFileUpload:       EP("/api/common/file/upload", MethodPOST),
			EPDatasetList:      EP("/api/proApi/datasets", MethodGET),
			EPDatasetCreate:    EP("/api/proApi/datasets", MethodPOST),
			EPDocumentUpload:   EP("/api/core/dataset/collection/create/localfile", MethodPOST),
			EPSearchQuery:      EP("/api/core/dataset/searchTest", MethodPOST),
			EPUserList:         EP("/api/proApi/users", MethodGET),
			EPConversationList: EP("/api/core/chat/getHistories", MethodGET),
			EPModelConfig:      EP("/api/model/config", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"fastgpt", "fast-gpt"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/version", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewLobeChatProfile() Profile {
	return &baseProfile{
		platform: core.PlatformLobeChat,
		name:     "LobeChat",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: true, PluginSystem: true,
			OAuth: true, Webhook: true, RAGPipeline: true,
		},
		defaultPorts: []int{3010, 8080},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:        EP("/api/auth/login", MethodPOST),
			EPChatCompletion:   EP("/api/chat/completions", MethodPOST, "/api/openai/chat/completions", MethodPOST),
			EPSystemVersion:    EP("/api/version", MethodGET),
			EPSystemHealth:     EP("/api/health", MethodGET),
			EPFileUpload:       EP("/api/files/upload", MethodPOST),
			EPPluginMarket:     EP("/api/market", MethodGET),
			EPUserList:         EP("/api/users", MethodGET),
			EPUserProfile:      EP("/api/profile", MethodGET),
			EPConversationList: EP("/api/conversations", MethodGET),
			EPSearchQuery:      EP("/api/rag/search", MethodPOST),
			EPKnowledgeBase:    EP("/api/knowledge-bases", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"lobechat", "lobe-chat", "lobehub"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/version", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewNextChatProfile() Profile {
	return &baseProfile{
		platform: core.PlatformNextChat,
		name:     "NextChat",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: false, OAuth: true,
		},
		defaultPorts: []int{3000},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:      EP("/api/auth", MethodPOST),
			EPChatCompletion: EP("/api/openai/v1/chat/completions", MethodPOST),
			EPSystemConfig:   EP("/api/config", MethodGET),
			EPSystemHealth:   EP("/api/health", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"nextchat", "chatgpt-next-web", "__NEXT_DATA__"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/config", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewAnythingLLMProfile() Profile {
	return &baseProfile{
		platform: core.PlatformAnythingLLM,
		name:     "AnythingLLM",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: true, RAGPipeline: true,
			AdminPanel: true,
		},
		defaultPorts: []int{3001},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:      EP("/api/auth/login", MethodPOST),
			EPAuthToken:      EP("/api/auth/token", MethodPOST),
			EPChatCompletion: EP("/api/v1/workspace/chat", MethodPOST),
			EPSystemVersion:  EP("/api/version", MethodGET),
			EPSystemHealth:   EP("/api/health", MethodGET),
			EPAdminPanel:     EP("/admin", MethodGET),
			EPFileUpload:     EP("/api/v1/document/upload", MethodPOST),
			EPFileList:       EP("/api/v1/documents", MethodGET),
			EPDatasetList:    EP("/api/v1/workspaces", MethodGET),
			EPSearchQuery:    EP("/api/v1/workspace/{slug}/vector-search", MethodPOST),
			EPUserList:       EP("/api/v1/users", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"anythingllm", "anything-llm"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/version", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewFlowiseProfile() Profile {
	return &baseProfile{
		platform: core.PlatformFlowise,
		name:     "Flowise",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: true, WorkflowEngine: true,
			MultiTenant: true, Webhook: true,
		},
		defaultPorts: []int{3000},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:        EP("/api/v1/auth/login", MethodPOST),
			EPChatCompletion:   EP("/api/v1/prediction", MethodPOST, "/api/v2/prediction", MethodPOST),
			EPSystemVersion:    EP("/api/v1/version", MethodGET),
			EPSystemHealth:     EP("/healthz", MethodGET),
			EPAdminPanel:       EP("/admin", MethodGET),
			EPFileUpload:       EP("/api/v1/file-upload", MethodPOST),
			EPFileList:         EP("/api/v1/files", MethodGET),
			EPWorkflowList:     EP("/api/v1/chatflows", MethodGET),
			EPWorkflowRun:      EP("/api/v1/chatflows/{id}", MethodGET),
			EPUserList:         EP("/api/v1/users", MethodGET),
			EPToolList:         EP("/api/v1/tools", MethodGET),
			EPToolInvoke:       EP("/api/v1/tools/{id}/invoke", MethodPOST),
			EPConversationList: EP("/api/v1/chatflows", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"flowise", "flowiseai"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/v1/version", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewRagFlowProfile() Profile {
	return &baseProfile{
		platform: core.PlatformRagFlow,
		name:     "RagFlow",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: true, RAGPipeline: true,
			WorkflowEngine: true, MultiTenant: true,
		},
		defaultPorts: []int{9380},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:        EP("/api/v1/login", MethodPOST),
			EPChatCompletion:   EP("/api/v1/chats/{id}/completions", MethodPOST),
			EPSystemVersion:    EP("/api/v1/version", MethodGET),
			EPSystemHealth:     EP("/health", MethodGET),
			EPAdminPanel:       EP("/admin", MethodGET),
			EPFileUpload:       EP("/api/v1/datasets/{id}/documents", MethodPOST),
			EPFileList:         EP("/api/v1/documents", MethodGET),
			EPDatasetList:      EP("/api/v1/datasets", MethodGET),
			EPDatasetCreate:    EP("/api/v1/datasets", MethodPOST),
			EPSearchQuery:      EP("/api/v1/retrieval", MethodPOST),
			EPUserList:         EP("/api/v1/users", MethodGET),
			EPConversationList: EP("/api/v1/chats", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"ragflow", "rag-flow"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/v1/version", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewLibreChatProfile() Profile {
	return &baseProfile{
		platform: core.PlatformLibreChat,
		name:     "LibreChat",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: true, OAuth: true,
			PluginSystem: true, Webhook: true, MCP: true, MultiTenant: true,
		},
		defaultPorts: []int{3080, 8080},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:        EP("/api/auth/login", MethodPOST),
			EPAuthRegister:     EP("/api/auth/register", MethodPOST),
			EPChatCompletion:   EP("/api/chat/completions", MethodPOST),
			EPSystemConfig:     EP("/api/config", MethodGET),
			EPSystemHealth:     EP("/health", MethodGET),
			EPFileUpload:       EP("/api/files", MethodPOST),
			EPFileList:         EP("/api/files", MethodGET),
			EPToolList:         EP("/api/tools", MethodGET),
			EPPluginMarket:     EP("/api/plugins", MethodGET),
			EPMcpServer:        EP("/api/mcp", MethodGET),
			EPUserList:         EP("/api/users", MethodGET),
			EPUserProfile:      EP("/api/user", MethodGET),
			EPConversationList: EP("/api/conversations", MethodGET),
			EPOAuthCallback:    EP("/api/auth/callback", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"librechat", "libre-chat"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/config", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewLangflowProfile() Profile {
	return &baseProfile{
		platform: core.PlatformLangflow,
		name:     "Langflow",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: true, WorkflowEngine: true,
			AdminPanel: true, MCP: true, PluginSystem: true, Sandbox: true,
		},
		defaultPorts: []int{7860, 3000},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:      EP("/api/v1/login", MethodPOST),
			EPChatCompletion: EP("/api/v1/run", MethodPOST),
			EPSystemVersion:  EP("/api/v1/version", MethodGET),
			EPSystemHealth:   EP("/health", MethodGET),
			EPAdminPanel:     EP("/admin", MethodGET),
			EPFileUpload:     EP("/api/v1/files", MethodPOST),
			EPWorkflowRun:    EP("/api/v1/flows/run", MethodPOST),
			EPWorkflowList:   EP("/api/v1/flows", MethodGET),
			EPFlowRun:        EP("/api/v1/flows/{id}/run", MethodPOST),
			EPFlowBuild:      EP("/api/v1/flows/build", MethodPOST),
			EPFlowList:       EP("/api/v1/flows", MethodGET),
			EPFlowExport:     EP("/api/v1/flows/{id}/export", MethodGET),
			EPUserList:       EP("/api/v1/users", MethodGET),
			EPUserCreate:     EP("/api/v1/users", MethodPOST),
			EPToolList:       EP("/api/v1/tools", MethodGET),
			EPMcpServer:      EP("/api/v1/mcp", MethodGET),
			EPMCPTest:        EP("/api/v1/mcp/test", MethodPOST),
			EPSandboxRun:     EP("/api/v1/sandbox/run", MethodPOST),
			EPApiToken:       EP("/api/v1/api_keys", MethodGET),
			EPFileRead:       EP("/api/v1/files", MethodGET),
			EPLogsQuery:      EP("/api/v1/logs", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"langflow", "lang-flow"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/v1/version", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewLiteLLMProfile() Profile {
	return &baseProfile{
		platform: core.PlatformLiteLLM,
		name:     "LiteLLM",
		caps: Capabilities{
			ChatCompletion: true, AdminPanel: true, MCP: true,
			MultiTenant: true, Webhook: true, OAuth: true,
		},
		defaultPorts: []int{4000},
		endpoints: map[EndpointKind]*Endpoint{
			EPAuthLogin:       EP("/login", MethodPOST),
			EPAuthToken:       EP("/token/generate", MethodPOST),
			EPChatCompletion:  EP("/chat/completions", MethodPOST, "/v1/chat/completions", MethodPOST),
			EPSystemVersion:   EP("/version", MethodGET),
			EPSystemHealth:    EP("/health", MethodGET),
			EPAdminPanel:      EP("/admin", MethodGET, "/ui", MethodGET),
			EPLLMProxy:        EP("/chat/completions", MethodPOST),
			EPModelList:       EP("/models", MethodGET, "/v1/models", MethodGET),
			EPUserList:        EP("/user/list", MethodGET),
			EPUserCreate:      EP("/user/new", MethodPOST),
			EPApiToken:        EP("/key/generate", MethodPOST),
			EPCredentialList:  EP("/credentials/list", MethodGET),
			EPCredentialStore: EP("/credentials/store", MethodPOST),
			EPMcpServer:       EP("/mcp", MethodGET),
			EPMCPTest:         EP("/mcp/test", MethodPOST),
			EPLogsQuery:       EP("/logs", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"litellm", "lite-llm"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/health", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/models", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewOllamaProfile() Profile {
	return &baseProfile{
		platform: core.PlatformOllama,
		name:     "Ollama",
		caps: Capabilities{
			ChatCompletion: true, FileUpload: true,
		},
		defaultPorts: []int{11434},
		endpoints: map[EndpointKind]*Endpoint{
			EPChatCompletion: EP("/api/chat", MethodPOST, "/api/generate", MethodPOST),
			EPSystemVersion:  EP("/api/version", MethodGET),
			EPSystemHealth:   EP("/api/tags", MethodGET),
			EPModelList:      EP("/api/tags", MethodGET),
			EPFileUpload:     EP("/api/create", MethodPOST),
			EPSandboxRun:     EP("/api/run", MethodPOST),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"ollama"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/tags", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewVLLMProfile() Profile {
	return &baseProfile{
		platform: core.PlatformVLLM,
		name:     "vLLM",
		caps: Capabilities{
			ChatCompletion: true,
		},
		defaultPorts: []int{8000},
		endpoints: map[EndpointKind]*Endpoint{
			EPChatCompletion: EP("/v1/chat/completions", MethodPOST),
			EPModelList:      EP("/v1/models", MethodGET),
			EPSystemHealth:   EP("/health", MethodGET),
			EPSystemVersion:  EP("/version", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"vllm", "v-litellm"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/v1/models", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewRayProfile() Profile {
	return &baseProfile{
		platform: core.PlatformRay,
		name:     "Ray Dashboard",
		caps: Capabilities{
			Sandbox: true, AdminPanel: true,
		},
		defaultPorts: []int{8265, 10001},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion: EP("/api/version", MethodGET),
			EPSystemHealth:  EP("/api/healthz", MethodGET),
			EPExecRun:       EP("/api/jobs/", MethodPOST),
			EPNodeList:      EP("/api/nodes/", MethodGET),
			EPLogsQuery:     EP("/api/logs", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"ray", "ray dashboard"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/version", Method: "GET", AcceptStatus: []int{200}, BodyContains: "ray"},
				{Path: "/api/healthz", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewMLflowProfile() Profile {
	return &baseProfile{
		platform: core.PlatformMLflow,
		name:     "MLflow",
		caps: Capabilities{
			AdminPanel: true, FileUpload: true,
		},
		defaultPorts: []int{5000, 5001},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion:    EP("/version", MethodGET),
			EPSystemHealth:     EP("/health", MethodGET),
			EPModelList:        EP("/api/2.0/mlflow/registered-models/list", MethodGET),
			EPFileUpload:       EP("/api/2.0/mlflow-artifacts/artifacts", MethodPOST),
			EPFileDownload:     EP("/get-artifact", MethodGET),
			EPConversationList: EP("/api/2.0/mlflow/experiments/search", MethodPOST),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"mlflow"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/health", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/version", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewGradioProfile() Profile {
	return &baseProfile{
		platform: core.PlatformGradio,
		name:     "Gradio",
		caps: Capabilities{
			FileUpload: true, ChatCompletion: true,
		},
		defaultPorts: []int{7860, 7861},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion:  EP("/info", MethodGET),
			EPSystemHealth:   EP("/health", MethodGET),
			EPFileUpload:     EP("/upload", MethodPOST),
			EPFileDownload:   EP("/file", MethodGET),
			EPChatCompletion: EP("/api/predict", MethodPOST, "/run/predict", MethodPOST),
			EPConfigGet:      EP("/config", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"gradio", "gradio-app"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/info", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/config", Method: "GET", AcceptStatus: []int{200}, BodyContains: "gradio"},
			},
		},
	}
}

func NewComfyUIProfile() Profile {
	return &baseProfile{
		platform: core.PlatformComfyUI,
		name:     "ComfyUI",
		caps: Capabilities{
			FileUpload: true, WorkflowEngine: true, WebSocket: true,
		},
		defaultPorts: []int{8188},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion: EP("/system_stats", MethodGET),
			EPFlowRun:       EP("/prompt", MethodPOST),
			EPFlowList:      EP("/history", MethodGET),
			EPFileUpload:    EP("/upload/image", MethodPOST),
			EPFileDownload:  EP("/view", MethodGET),
			EPNodeList:      EP("/object_info", MethodGET),
			EPModelList:     EP("/models/checkpoints", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"comfyui", "comfy"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/system_stats", Method: "GET", AcceptStatus: []int{200}, BodyContains: "comfyui"},
				{Path: "/object_info", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewDBGPTProfile() Profile {
	return &baseProfile{
		platform: core.PlatformDBGPT,
		name:     "DB-GPT",
		caps: Capabilities{
			ChatCompletion: true, RAGPipeline: true, Sandbox: true,
		},
		defaultPorts: []int{5670},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion:  EP("/api/v1/version", MethodGET),
			EPChatCompletion: EP("/api/v1/chat/completions", MethodPOST),
			EPModelList:      EP("/api/v1/models", MethodGET),
			EPFileUpload:     EP("/api/v1/knowledge/upload", MethodPOST),
			EPKnowledgeBase:  EP("/api/v1/knowledge/list", MethodGET),
			EPSandboxExec:    EP("/api/v1/editor/sql/run", MethodPOST),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"dbgpt", "db-gpt"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/v1/version", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/", Method: "GET", AcceptStatus: []int{200}, BodyContains: "DB-GPT"},
			},
		},
	}
}

func NewChromaDBProfile() Profile {
	return &baseProfile{
		platform: core.PlatformChromaDB,
		name:     "ChromaDB",
		caps: Capabilities{
			RAGPipeline: true,
		},
		defaultPorts: []int{8000, 8001},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion: EP("/api/v1/version", MethodGET),
			EPSystemHealth:  EP("/api/v1/heartbeat", MethodGET),
			EPDatasetList:   EP("/api/v1/collections", MethodGET),
			EPDatasetCreate: EP("/api/v1/collections", MethodPOST),
			EPVectorSearch:  EP("/api/v1/collections", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"chroma"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api/v1/version", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/api/v1/heartbeat", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewQdrantProfile() Profile {
	return &baseProfile{
		platform: core.PlatformQdrant,
		name:     "Qdrant",
		caps: Capabilities{
			RAGPipeline: true,
		},
		defaultPorts: []int{6333, 6334},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion: EP("/", MethodGET),
			EPSystemHealth:  EP("/healthz", MethodGET),
			EPDatasetList:   EP("/collections", MethodGET),
			EPDatasetCreate: EP("/collections", MethodPUT),
			EPVectorSearch:  EP("/collections", MethodGET),
			EPConfigGet:     EP("/cluster", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"qdrant"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/", Method: "GET", AcceptStatus: []int{200}, BodyContains: "qdrant"},
				{Path: "/collections", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewWeaviateProfile() Profile {
	return &baseProfile{
		platform: core.PlatformWeaviate,
		name:     "Weaviate",
		caps: Capabilities{
			RAGPipeline: true,
		},
		defaultPorts: []int{8080, 50051},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion: EP("/v1/meta", MethodGET),
			EPSystemHealth:  EP("/v1/.well-known/live", MethodGET),
			EPDatasetList:   EP("/v1/schema", MethodGET),
			EPVectorSearch:  EP("/v1/graphql", MethodPOST),
			EPAuthConfig:    EP("/v1/authz/users", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"weaviate"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/v1/meta", Method: "GET", AcceptStatus: []int{200}, BodyContains: "weaviate"},
				{Path: "/v1/.well-known/live", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewMilvusProfile() Profile {
	return &baseProfile{
		platform: core.PlatformMilvus,
		name:     "Milvus",
		caps: Capabilities{
			RAGPipeline: true,
		},
		defaultPorts: []int{19530, 9091},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion: EP("/v1/vector/collections", MethodGET),
			EPSystemHealth:  EP("/healthz", MethodGET),
			EPDatasetList:   EP("/v2/vectordb/collections/list", MethodPOST),
			EPVectorSearch:  EP("/v2/vectordb/entities/search", MethodPOST),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"milvus"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/healthz", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/v2/vectordb/collections/list", Method: "POST", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewLocalAIProfile() Profile {
	return &baseProfile{
		platform: core.PlatformLocalAI,
		name:     "LocalAI",
		caps: Capabilities{
			ChatCompletion: true, Audio: true, FileUpload: true,
		},
		defaultPorts: []int{8080},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion:  EP("/api/version", MethodGET),
			EPChatCompletion: EP("/v1/chat/completions", MethodPOST),
			EPModelList:      EP("/v1/models", MethodGET),
			EPModelConfig:    EP("/models/apply", MethodPOST),
			EPAudioSpeech:    EP("/v1/audio/speech", MethodPOST),
			EPFileUpload:     EP("/v1/audio/transcriptions", MethodPOST),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"localai", "local-ai"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/v1/models", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/api/version", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewXinferenceProfile() Profile {
	return &baseProfile{
		platform: core.PlatformXinference,
		name:     "Xinference",
		caps: Capabilities{
			ChatCompletion: true, AdminPanel: true, Audio: true,
		},
		defaultPorts: []int{9997},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion:  EP("/v1/version", MethodGET),
			EPChatCompletion: EP("/v1/chat/completions", MethodPOST),
			EPModelList:      EP("/v1/models", MethodGET),
			EPModelConfig:    EP("/v1/models", MethodPOST),
			EPAdminPanel:     EP("/v1/cluster/info", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"xinference"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/v1/version", Method: "GET", AcceptStatus: []int{200}},
				{Path: "/v1/models", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}

func NewJupyterProfile() Profile {
	return &baseProfile{
		platform: core.PlatformJupyter,
		name:     "Jupyter",
		caps: Capabilities{
			Sandbox: true, FileUpload: true, AdminPanel: true,
		},
		defaultPorts: []int{8888, 8889},
		endpoints: map[EndpointKind]*Endpoint{
			EPSystemVersion: EP("/api", MethodGET),
			EPSystemHealth:  EP("/api/status", MethodGET),
			EPSessionList:   EP("/api/sessions", MethodGET),
			EPFileList:      EP("/api/contents", MethodGET),
			EPSandboxExec:   EP("/api/kernels", MethodPOST),
			EPConfigGet:     EP("/api/config", MethodGET),
		},
		fingerprint: FingerprintSpec{
			BodyKeywords: []string{"jupyter", "notebook"},
			ProbeEndpoints: []ProbeEndpoint{
				{Path: "/api", Method: "GET", AcceptStatus: []int{200}, BodyContains: "jupyter"},
				{Path: "/api/status", Method: "GET", AcceptStatus: []int{200}},
			},
		},
	}
}
