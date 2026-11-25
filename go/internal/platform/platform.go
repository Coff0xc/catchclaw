package platform

import (
	"github.com/Coff0xc/catchclaw/go/internal/core"
)

type EndpointKind int

const (
	EPAuthLogin EndpointKind = iota
	EPAuthRegister
	EPAuthToken
	EPAuthConfig
	EPChatCompletion
	EPChatMessages
	EPStreamingChat
	EPSystemConfig
	EPSystemVersion
	EPSystemHealth
	EPAdminPanel
	EPFileUpload
	EPFileList
	EPFileDownload
	EPToolList
	EPToolInvoke
	EPPluginMarket
	EPSkillList
	EPMcpServer
	EPWorkflowRun
	EPWorkflowList
	EPDatasetList
	EPDatasetCreate
	EPDocumentUpload
	EPSearchQuery
	EPWebhookEndpoint
	EPWebSocketGateway
	EPAudioSpeech
	EPAudioTranscription
	EPUserList
	EPUserProfile
	EPConversationList
	EPConversationExport
	EPOAuthCallback
	EPOAuthAuthorize
	EPLLMProxy
	EPModelList
	EPVectorSearch
	EPSandboxExec
	EPSkillInstall
	EPSkillMarketplace
	EPPluginDaemon
	EPFlowRun
	EPFlowList
	EPNodeList
	EPNodeConnect
	EPCredentialList
	EPCredentialStore
	EPSecretList
	EPSecretGet
	EPSessionList
	EPSessionPreview
	EPSessionPatch
	EPTalkConfig
	EPTalkSecrets
	EPLogsQuery
	EPExecRun
	EPExecApproval
	EPConfigSet
	EPConfigGet
	EPPairingCode
	EPBrowserNavigate
	EPBrowserRequest
	EPAgentCreate
	EPAgentUpdate
	EPAgentFiles
	EPCronList
	EPCronSet
	EPSkillScan
	EPUploadFile
	EPKnowledgeBase
	EPModelConfig
	EPSandboxRun
	EPMCPTest
	EPFlowBuild
	EPFlowExport
	EPUserCreate
	EPFileRead
	EPApiToken
	EPTenantSwitch
)

type HTTPMethod string

const (
	MethodGET    HTTPMethod = "GET"
	MethodPOST   HTTPMethod = "POST"
	MethodPUT    HTTPMethod = "PUT"
	MethodDELETE HTTPMethod = "DELETE"
	MethodPATCH  HTTPMethod = "PATCH"
)

type Endpoint struct {
	Path      string
	Method    HTTPMethod
	Fallbacks []string
}

type ProbeEndpoint struct {
	Path          string
	Method        string
	AcceptStatus  []int
	BodyContains  string
}

type FingerprintSpec struct {
	BodyKeywords  []string
	HeaderMarkers map[string]string
	ProbeEndpoints []ProbeEndpoint
}

type Capabilities struct {
	ChatCompletion  bool
	WebSocket       bool
	FileUpload      bool
	AdminPanel      bool
	PluginSystem    bool
	WorkflowEngine  bool
	RAGPipeline     bool
	OAuth           bool
	Webhook         bool
	Audio           bool
	MCP             bool
	MultiTenant     bool
	SkillSystem     bool
	Sandbox         bool
}

type Profile interface {
	Platform() core.Platform
	Name() string
	Capabilities() Capabilities
	Resolve(kind EndpointKind) *Endpoint
	Fingerprint() FingerprintSpec
	DefaultPorts() []int
}

type Registry struct {
	profiles map[core.Platform]Profile
}

func NewRegistry() *Registry {
	return &Registry{profiles: make(map[core.Platform]Profile)}
}

func (r *Registry) Register(p Profile) {
	r.profiles[p.Platform()] = p
}

func (r *Registry) Get(p core.Platform) Profile {
	return r.profiles[p]
}

func (r *Registry) All() []Profile {
	var profiles []Profile
	for _, p := range r.profiles {
		profiles = append(profiles, p)
	}
	return profiles
}

var global = NewRegistry()

func init() {
	global.Register(NewOpenClawProfile())
	global.Register(NewDifyProfile())
	global.Register(NewFastGPTProfile())
	global.Register(NewLobeChatProfile())
	global.Register(NewNextChatProfile())
	global.Register(NewAnythingLLMProfile())
	global.Register(NewFlowiseProfile())
	global.Register(NewRagFlowProfile())
	global.Register(NewLibreChatProfile())
	global.Register(NewLangflowProfile())
	global.Register(NewLiteLLMProfile())
	global.Register(NewOllamaProfile())
	global.Register(NewVLLMProfile())
	global.Register(NewRayProfile())
	global.Register(NewMLflowProfile())
	global.Register(NewGradioProfile())
	global.Register(NewComfyUIProfile())
	global.Register(NewDBGPTProfile())
	global.Register(NewChromaDBProfile())
	global.Register(NewQdrantProfile())
	global.Register(NewWeaviateProfile())
	global.Register(NewMilvusProfile())
	global.Register(NewLocalAIProfile())
	global.Register(NewXinferenceProfile())
	global.Register(NewJupyterProfile())
}

func Global() *Registry {
	return global
}

func Resolve(p core.Platform, kind EndpointKind) *Endpoint {
	profile := global.Get(p)
	if profile == nil {
		return nil
	}
	return profile.Resolve(kind)
}
