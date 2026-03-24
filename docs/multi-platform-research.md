# Multi-Platform AI Agent Security Research

> CatchClaw v5.2.0 — Cross-Platform Expansion Research
> Date: 2026-03-24

---

## 1. Dify (langgenius/dify)

### 1.1 Fingerprint

| Type | Signature |
|------|-----------|
| HTML Keywords | `Dify`, `dify-ai`, `dify.ai` |
| Response Headers | `X-Version` (Dify version), Flask/Werkzeug server header |
| Characteristic Endpoints | `GET /console/api/setup`, `GET /console/api/version`, `GET /api/v1/parameters` |
| Default Port | **5001** (API), **3000** (Web frontend) |
| Deployment | Docker Compose (nginx + api + web + worker + db + redis + weaviate) |

### 1.2 API Route Structure

**Controller Layout**: `api/controllers/` with subdirectories: `console/`, `service_api/`, `web/`, `files/`, `inner_api/`, `mcp/`, `common/`, `trigger/`

| Category | Endpoints |
|----------|-----------|
| **Auth** | `/console/api/login`, `/console/api/setup`, `/console/api/oauth/...` |
| **App/Chat** | `/console/api/apps/{id}/...`, `/v1/chat-messages`, `/v1/completion-messages` |
| **Workflow** | `/v1/workflows/run`, `/v1/workflows/tasks/{id}/stop` |
| **Dataset/RAG** | `/console/api/datasets/...`, `/v1/datasets/{id}/document/create-by-text`, `/v1/datasets/{id}/document/create-by-file` |
| **Files** | `/console/api/files/upload`, `/files/{id}/...` |
| **Admin** | `/console/api/admin/...` (user mgmt, system settings) |
| **Workspace** | `/console/api/workspace/...` (members, model providers) |
| **MCP** | `/console/api/mcp/...` (Model Context Protocol integration) |
| **Billing** | `/console/api/billing/...` |
| **Plugins** | `/console/api/workspaces/current/plugin/...` |
| **Health** | `/console/api/ping`, `/v1/metrics` (internal OTel) |

### 1.3 Known CVEs

| CVE | Type | CVSS | Fixed |
|-----|------|------|-------|
| CVE-2025-56157 | Default PostgreSQL credentials in docker-compose.yaml | Critical | v1.5.2+ |
| CVE-2025-55182 | React Server Components RCE | Critical | v1.11.1 |
| CVE-2025-55184 | React Server Components data leakage | High | v1.11.1 |
| CVE-2025-67779 | React unsafe state reuse | High | v1.11.1 |

### 1.4 OpenClaw Similarity & Exploit Reuse

| Similarity | Detail |
|------------|--------|
| **High** | REST API with Bearer token auth, chat completion streaming, file upload endpoints |
| **Reusable Exploits** | SSRF (via workflow HTTP nodes), prompt injection (chat/completion), auth bypass (default creds), file upload abuse |
| **Unique Attack Surface** | Workflow engine (code execution nodes), plugin system, MCP integration, dataset/RAG poisoning |

---

## 2. FastGPT (labring/FastGPT)

### 2.1 Fingerprint

| Type | Signature |
|------|-----------|
| HTML Keywords | `FastGPT`, `fastgpt`, `Sealos` |
| Response Headers | Next.js `X-Powered-By: Next.js`, custom `X-FastGPT-*` headers |
| Characteristic Endpoints | `GET /api/system/getInitData`, `GET /api/openapi.json` |
| Default Port | **3000** |
| Deployment | Docker Compose / Sealos cloud (MongoDB + PostgreSQL + OneAPI) |

### 2.2 API Route Structure

**Layout**: Next.js pages router at `projects/app/src/pages/api/` with subdirectories: `admin/`, `aiproxy/`, `common/`, `core/`, `invoke/`, `lafApi/`, `marketplace/`, `mcp/`, `plugin/`, `proApi/`, `support/`, `system/`, `v1/`, `v2/`

| Category | Endpoints |
|----------|-----------|
| **Auth** | `/api/support/user/account/login`, `/api/support/user/account/register` |
| **Chat/Completion** | `/api/v1/chat/completions` (OpenAI-compatible), `/api/core/chat/...` |
| **Dataset/KB** | `/api/core/dataset/...` (CRUD, collections, create-by-text/file/link) |
| **App/Workflow** | `/api/core/app/...`, `/api/core/workflow/...` |
| **Files** | `/api/core/dataset/collection/create/localFile`, `/api/common/file/...` |
| **Plugins** | `/api/core/app/plugin/...`, `/api/plugin/...` |
| **Admin** | `/api/admin/...` |
| **AI Proxy** | `/api/aiproxy/...` (model provider proxy) |
| **MCP** | `/api/mcp/...` |
| **System** | `/api/system/getInitData`, `/api/system/getEnv` |
| **Marketplace** | `/api/marketplace/...` |

### 2.3 Known CVEs

| CVE | Type | CVSS | Fixed |
|-----|------|------|-------|
| CVE-2026-33075 | Supply chain attack via GitHub Actions (CI/CD compromise) | Critical (9.x) | Not patched at disclosure |
| CVE-2025-52552 | Open Redirect + DOM-based XSS via LastRoute param | High | v4.9.12 |
| CVE-2025-62612 | SSRF in workflow file reading node | High | v4.11.1 |
| CVE-2025-27600 | SSRF via web crawling plugin (no intranet IP check) | High | v4.9.0 |

### 2.4 OpenClaw Similarity & Exploit Reuse

| Similarity | Detail |
|------------|--------|
| **High** | OpenAI-compatible `/v1/chat/completions`, dataset/knowledge base CRUD, file upload |
| **Reusable Exploits** | SSRF (web crawl, file read nodes), prompt injection, auth bypass, XSS |
| **Unique Attack Surface** | Workflow nodes with HTTP fetch, AI proxy (key leakage), marketplace plugin supply chain |

---

## 3. NextChat / ChatGPT-Next-Web (ChatGPTNextWeb/NextChat)

### 3.1 Fingerprint

| Type | Signature |
|------|-----------|
| HTML Keywords | `NextChat`, `ChatGPT Next Web`, `chatgpt-next-web` |
| Response Headers | `X-Powered-By: Next.js` |
| Characteristic Endpoints | `/api/config`, `/api/openai/[...path]`, `/api/proxy` |
| Default Port | **3000** |
| Deployment | Vercel / Docker / standalone Node.js |

### 3.2 API Route Structure

**Layout**: Next.js App Router at `app/api/` — primarily LLM provider proxies

| Category | Endpoints |
|----------|-----------|
| **Auth** | `CODE` env var password check (in `/api/auth.ts`), no user system |
| **LLM Proxy** | `/api/openai/[...path]`, `/api/anthropic/[...path]`, `/api/google/[...path]`, `/api/azure/[...path]` |
| **Provider-specific** | `/api/baidu.ts`, `/api/bytedance.ts`, `/api/deepseek.ts`, `/api/glm.ts`, `/api/moonshot.ts`, `/api/xai.ts`, `/api/siliconflow.ts`, `/api/iflytek.ts`, `/api/alibaba.ts`, `/api/302ai.ts` |
| **Proxy/CORS** | `/api/proxy` (general proxy — **SSRF vector**), `/api/[provider]/[...path]` |
| **WebDAV** | `/api/webdav/[...path]` (sync storage) |
| **Config** | `/api/config/` |
| **Artifacts** | `/api/artifacts/` |
| **Stability** | `/api/stability.ts` (image gen) |

### 3.3 Known CVEs

| CVE | Type | CVSS | Fixed |
|-----|------|------|-------|
| CVE-2023-49785 | Critical SSRF/XSS via `/api/cors` open proxy | 9.1 Critical | v2.12.2 |

**Note**: 7,500+ exposed instances on Shodan. The `/api/cors` (now `/api/proxy`) endpoint acts as an open proxy allowing SSRF to internal networks.

### 3.4 OpenClaw Similarity & Exploit Reuse

| Similarity | Detail |
|------------|--------|
| **Medium** | LLM proxy pattern similar to OpenClaw Gateway, but no user/workspace management |
| **Reusable Exploits** | SSRF (proxy endpoint), API key leakage (env var exposure), prompt injection via chat |
| **Unique Attack Surface** | Open CORS proxy, WebDAV integration, multi-provider API key exposure, Cloudflare AI Gateway bypass |

---

## 4. AnythingLLM (Mintplex-Labs/anything-llm)

### 4.1 Fingerprint

| Type | Signature |
|------|-----------|
| HTML Keywords | `AnythingLLM`, `anything-llm`, `Mintplex Labs` |
| Response Headers | Express.js headers, `X-Powered-By: Express` |
| Characteristic Endpoints | `/api/docs` (Swagger UI), `/api/v1/auth`, `/api/ping` |
| Default Port | **3001** |
| Deployment | Docker / Desktop app (Electron) / standalone Node.js |

### 4.2 API Route Structure

**Layout**: Express.js at `server/endpoints/` — file-per-resource pattern

| Category | Endpoints |
|----------|-----------|
| **Auth** | `/api/v1/auth/...`, `/api/request-token` |
| **Admin** | `admin.js` — user management, system preferences, multi-user config |
| **System** | `system.js` — 45KB+ of system settings, LLM/embedding/vector config, export/import |
| **Workspaces** | `workspaces.js` — CRUD, document management, pinning, settings |
| **Chat** | `chat.js` — workspace chat, streaming responses |
| **Documents** | `document.js` — document upload, processing |
| **Workspace Threads** | `workspaceThreads.js` — threaded conversations |
| **Agent Flows** | `agentFlows.js` — AI agent workflow management |
| **Agent WebSocket** | `agentWebsocket.js` — real-time agent communication |
| **Embed** | `embed/` — embeddable chat widget endpoints |
| **Extensions** | `extensions/` — plugin/extension management |
| **Browser Extension** | `browserExtension.js` — browser extension API |
| **MCP Servers** | `mcpServers.js` — MCP server management |
| **Invites** | `invite.js` — user invitation system |
| **Community Hub** | `communityHub.js` — community plugin/template hub |
| **Telegram** | `telegram.js` — Telegram bot integration |
| **Swagger Docs** | `/api/docs` (disable via `DISABLE_SWAGGER_DOCS`) |

### 4.3 Known CVEs

| CVE | Type | CVSS | Fixed |
|-----|------|------|-------|
| CVE-2024-13059 | Path traversal + RCE via non-ASCII filenames (multer) | 9.1 Critical | v1.3.1 |
| CVE-2024-0455 | EC2 credential exposure via web scraper (SSRF to metadata) | High | Patched |
| CVE-2026-21484 | Username enumeration via password recovery | Medium | Patched |
| (No CVE) | Zip Slip path traversal in community plugin import (v1.11.1) | High | Patched |
| (No CVE) | Suspended user bypass via browser extension API key | Medium | Patched |
| (No CVE) | Manager role can read plaintext DB creds via system-preferences | High | Patched |

### 4.4 OpenClaw Similarity & Exploit Reuse

| Similarity | Detail |
|------------|--------|
| **High** | Workspace-based chat, document upload, admin panel, API key auth |
| **Reusable Exploits** | SSRF (web scraper), path traversal (file upload), auth bypass, credential exposure |
| **Unique Attack Surface** | Swagger docs exposure, browser extension API bypass, Electron desktop app, community hub supply chain |

---

## 5. Flowise (FlowiseAI/Flowise)

### 5.1 Fingerprint

| Type | Signature |
|------|-----------|
| HTML Keywords | `Flowise`, `FlowiseAI`, `flowise` |
| Response Headers | Express.js headers |
| Characteristic Endpoints | `/api/v1/ping`, `/api/v1/chatflows`, `/api/v1/predictions/{id}` |
| Default Port | **3000** |
| Deployment | Docker / npm / npx (`npx flowise start`) |

### 5.2 API Route Structure

**Layout**: Express.js at `packages/server/src/routes/` — directory-per-resource (~50 route directories)

| Category | Endpoints |
|----------|-----------|
| **Auth/API Keys** | `apikey/`, `oauth2/`, `verify/` |
| **Chatflows** | `chatflows/`, `chatflows-streaming/`, `chatflows-uploads/` |
| **Predictions** | `predictions/` — runtime chat/inference endpoint |
| **Assistants** | `assistants/`, `openai-assistants/`, `openai-assistants-files/`, `openai-assistants-vector-store/` |
| **Attachments/Files** | `attachments/`, `files/`, `get-upload-file/` |
| **Credentials** | `credentials/`, `components-credentials/`, `components-credentials-icon/` |
| **Document Store** | `documentstore/`, `dataset/`, `vectors/` |
| **Tools** | `tools/`, `nodes/`, `node-configs/`, `node-custom-functions/`, `node-icons/`, `node-load-methods/` |
| **Agent Flow** | `agentflowv2-generator/`, `executions/` |
| **Chat Messages** | `chat-messages/`, `internal-chat-messages/` |
| **Settings/Variables** | `settings/`, `variables/`, `flow-config/` |
| **Marketplace** | `marketplaces/` |
| **Public** | `public-chatbots/`, `public-chatflows/`, `public-executions/` |
| **Admin** | `leads/`, `feedback/`, `stats/`, `log/`, `evaluations/`, `evaluator/` |
| **Export/Import** | `export-import/`, `versions/` |
| **Misc** | `ping/`, `pricing/`, `prompts-lists/`, `load-prompts/`, `fetch-links/`, `text-to-speech/`, `upsert-history/`, `validation/`, `nvidia-nim/`, `openai-realtime/` |

### 5.3 Known CVEs

| CVE | Type | CVSS | Fixed |
|-----|------|------|-------|
| CVE-2024-31621 | Auth bypass + RCE via `/api/v1` | Critical | v1.6.3+ |
| CVE-2025-26319 | Arbitrary file upload via `/api/v1/attachments` (Content-Type spoof) | High | v1.6.6+ |
| CVE-2025-58434 | Unauth password reset token disclosure (account takeover) | 9.8 Critical | v3.0.5 |
| CVE-2025-59528 | RCE via CustomMCP node (Function() constructor) | Critical | v3.0.6 |
| CVE-2025-8943 | Unauth RCE via Custom MCPs (npx command execution) | Critical | v3.0.1 |
| (Pending) | Mass assignment on `/api/v1/leads` (no auth, Object.assign) | Medium | v3.0.13+ |

### 5.4 OpenClaw Similarity & Exploit Reuse

| Similarity | Detail |
|------------|--------|
| **High** | Flow/workflow execution, tool/plugin management, file upload, API key auth, public chatbot endpoints |
| **Reusable Exploits** | Auth bypass, file upload abuse, RCE (code execution nodes), credential exposure |
| **Unique Attack Surface** | **No auth by default** (< v3.0.1), CustomMCP code injection, visual flow manipulation, public-facing prediction endpoint, marketplace templates |

---

## 6. RagFlow (infiniflow/ragflow)

### 6.1 Fingerprint

| Type | Signature |
|------|-----------|
| HTML Keywords | `RAGFlow`, `ragflow`, `infiniflow` |
| Response Headers | Flask/Werkzeug headers |
| Characteristic Endpoints | `/v1/api/...`, `/api/...` (Flask routes) |
| Default Port | **9380** (API), **80** (Web via nginx) |
| Deployment | Docker Compose (api + web + elasticsearch + mysql + redis + minio) |

### 6.2 API Route Structure

**Layout**: Flask at `api/apps/` — file-per-resource pattern

| Category | Endpoints |
|----------|-----------|
| **Auth** | `auth/` directory — login, register, OAuth |
| **User** | `user_app.py` — user profile, settings, API tokens (34KB) |
| **Tenant** | `tenant_app.py` — multi-tenant management |
| **Knowledge Base** | `kb_app.py` — knowledge base CRUD (38KB) |
| **Document** | `document_app.py` — document upload, parsing, web_crawl (41KB, **SSRF vector**) |
| **Chunk** | `chunk_app.py` — chunk management, search (25KB) |
| **Conversation** | `conversation_app.py` — chat/dialogue management (18KB) |
| **Dialog** | `dialog_app.py` — dialog/assistant configuration |
| **Canvas/Workflow** | `canvas_app.py` — visual workflow canvas (30KB) |
| **File** | `file_app.py` — file management (18KB) |
| **Search** | `search_app.py` — search/retrieval API |
| **LLM** | `llm_app.py` — LLM provider configuration (20KB) |
| **Connector** | `connector_app.py` — external data connectors (19KB) |
| **System** | `system_app.py` — system configuration |
| **Plugin** | `plugin_app.py` — plugin management |
| **Evaluation** | `evaluation_app.py` — RAG evaluation |
| **MCP** | `mcp_server_app.py` — MCP server integration |
| **API Gateway** | `api_app.py` — external API access |
| **SDK** | `sdk/` — Python SDK endpoints |
| **RESTful APIs** | `restful_apis/` — versioned REST API |
| **Services** | `services/` — background services |
| **Langfuse** | `langfuse_app.py` — observability integration |

### 6.3 Known CVEs

| CVE | Type | CVSS | Fixed |
|-----|------|------|-------|
| CVE-2024-12433 | RCE via pickle deserialization + hardcoded RPC AuthKey | 9.8 Critical | v0.14.0 |
| CVE-2024-12450 | SSRF + arbitrary file read + RCE via web_crawl (no URL filter + old Chromium) | 6.5 Moderate | v0.14.0 |
| CVE-2024-12880 | Partial account takeover via tenant API token access | 8.1 High | Pending |
| CVE-2024-12871 | XSS via malicious PDF upload to knowledge base | Medium | Pending |

### 6.4 OpenClaw Similarity & Exploit Reuse

| Similarity | Detail |
|------------|--------|
| **High** | Flask backend, document/file upload, knowledge base, chat/conversation, multi-tenant |
| **Reusable Exploits** | SSRF (web_crawl), file upload XSS, auth bypass, RCE (deserialization) |
| **Unique Attack Surface** | Pickle deserialization RCE, hardcoded RPC auth key, Chromium sandbox escape, tenant isolation bypass, Elasticsearch injection |

---

## Cross-Platform Comparison Matrix

### Common Attack Surface

| Attack Category | Dify | FastGPT | NextChat | AnythingLLM | Flowise | RagFlow | OpenClaw |
|----------------|------|---------|----------|-------------|---------|---------|----------|
| SSRF | Y | Y | Y (Critical) | Y | - | Y | Y |
| File Upload Abuse | Y | Y | - | Y | Y (Critical) | Y | Y |
| Auth Bypass | Y (default creds) | - | - | Y | Y (no auth default) | - | - |
| RCE | Y (React) | - | - | Y (path trav) | Y (MCP/code injection) | Y (pickle) | - |
| Prompt Injection | Y | Y | Y | Y | Y | Y | Y |
| XSS | - | Y | Y | - | - | Y | - |
| Credential Leak | Y (pg creds) | - | Y (API keys) | Y (EC2/DB creds) | Y (reset token) | Y (RPC key) | - |
| Account Takeover | - | - | - | - | Y | Y | - |

### Shared Endpoint Patterns (Exploit Reuse Candidates)

| Pattern | Platforms | CatchClaw Module Mapping |
|---------|-----------|------------------------|
| `/v1/chat/completions` (OpenAI-compat) | Dify, FastGPT, RagFlow | `prompt_inject`, `llm_abuse` |
| `/api/v1/files/upload` or equivalent | All 6 | `file_upload`, `path_traversal` |
| `/api/v1/datasets/...` or `/kb/...` | Dify, FastGPT, Flowise, RagFlow | `rag_poisoning`, `data_exfil` |
| Workflow/Canvas execution | Dify, FastGPT, Flowise, RagFlow | `code_exec`, `ssrf` |
| Web crawl / URL fetch | Dify, FastGPT, NextChat, RagFlow | `ssrf` |
| Admin/system endpoints | Dify, AnythingLLM, Flowise, RagFlow | `auth_bypass`, `priv_esc` |
| API proxy / CORS bypass | NextChat, Dify | `ssrf`, `proxy_abuse` |
| Plugin/MCP/Tool management | Dify, FastGPT, AnythingLLM, Flowise, RagFlow | `supply_chain`, `rce` |
| Swagger/OpenAPI docs | AnythingLLM, Flowise, FastGPT | `info_disclosure` |

### Default Ports Summary

| Platform | Default Port(s) |
|----------|----------------|
| Dify | 5001 (API), 3000 (Web) |
| FastGPT | 3000 |
| NextChat | 3000 |
| AnythingLLM | 3001 |
| Flowise | 3000 |
| RagFlow | 9380 (API), 80 (Web) |
| OpenClaw | 8080 (Gateway) |

---

## Recommended CatchClaw Expansion Strategy

### Priority 1: Direct Exploit Reuse (Minimal Adaptation)
- **SSRF modules** → Dify (workflow HTTP), FastGPT (web crawl), NextChat (proxy), RagFlow (web_crawl)
- **Prompt injection** → All 6 platforms (OpenAI-compatible chat endpoints)
- **File upload abuse** → Dify, FastGPT, AnythingLLM, Flowise, RagFlow

### Priority 2: Platform-Specific Exploits
- **Flowise**: No-auth-by-default exploitation, CustomMCP RCE, attachment Content-Type bypass
- **RagFlow**: Pickle deserialization RCE, hardcoded RPC key, tenant isolation bypass
- **AnythingLLM**: Path traversal RCE (multer), SSRF to cloud metadata, Swagger exposure
- **NextChat**: Open proxy SSRF, WebDAV abuse, API key harvesting

### Priority 3: New Module Categories
- **RAG poisoning**: Dataset/knowledge base manipulation (Dify, FastGPT, RagFlow)
- **Supply chain**: Plugin/marketplace template injection (FastGPT, AnythingLLM, Flowise)
- **MCP abuse**: MCP server exploitation across all platforms supporting MCP
- **Workflow RCE**: Code execution node abuse (Dify, FastGPT, Flowise)
