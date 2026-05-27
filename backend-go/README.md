# MobileAgent Backend (Go)

Go 后端负责：

- Agent loop / tool calling
- APK 分析与逆向 API
- Device / Frida / MCP / Skills / Memory API
- SQLite 持久化

## 启动

```bash
make build
make run
```

或：

```bash
go build -o build/mobileagent-server ./cmd/server
./build/mobileagent-server -config configs/config.yaml
```

## 验证

```bash
go test ./...
go build ./cmd/server
```

## 配置

配置文件：

```text
configs/config.yaml
```

主要模块：

- `server`
- `adb`
- `llm`
- `tools`
- `storage`
- `agent`
- `skills`
- `sandbox`
- `mcp`

## 主要路由

### Agent

- `POST /api/v1/chat`
- `POST /api/v1/chat/approve`
- `GET /api/v1/conversations`
- `GET /api/v1/conversations/:id`
- `DELETE /api/v1/conversations/:id`
- `POST /api/v1/conversations/:id/rollback`

### APK

- `GET /api/v1/apk`
- `POST /api/v1/apk/analyze`
- `POST /api/v1/apk/decompile`
- `POST /api/v1/apk/build`
- `POST /api/v1/apk/sign`
- `POST /api/v1/apk/install`
- `GET /api/v1/apk/:id/analyses`
- `POST /api/v1/apk/:id/analyze/manifest`
- `POST /api/v1/apk/:id/analyze/certificate`
- `POST /api/v1/apk/:id/analyze/risk`
- `POST /api/v1/apk/:id/analyze/attack_surface`
- `POST /api/v1/apk/:id/analyze/entry_trace`
- `POST /api/v1/apk/:id/analyze/packer`
- `POST /api/v1/apk/:id/analyze/code`
- `POST /api/v1/apk/:id/analyze/sdk`
- `POST /api/v1/apk/:id/analyze/strings`
- `POST /api/v1/apk/:id/analyze/antidetect`
- `POST /api/v1/apk/:id/analyze/triage`
- `POST /api/v1/apk/:id/analyze/all`
- `POST /api/v1/apk/:id/runtime_plan`
- `GET /api/v1/apk/:id/report`
- `GET /api/v1/apk/:id/evidence_package`
- `GET /api/v1/apk/:id/hooks`
- `GET /api/v1/apk/:id/callgraph`
- `GET /api/v1/apk/diff`

### Device / Frida / MCP / Memory

- `GET /api/v1/devices`
- `POST /api/v1/devices/:serial/shell`
- `POST /api/v1/devices/:serial/screenshot`
- `POST /api/v1/devices/:serial/packages`
- `POST /api/v1/devices/:serial/connect`
- `GET /api/v1/frida/scripts`
- `POST /api/v1/frida/run`
- `GET /api/v1/mcp/tools`
- `GET /api/v1/skills`
- `GET /api/v1/memory`

## 当前内置逆向相关技能

- `apk_list`
- `apk_decompile`
- `apk_triage`
- `apk_attack_surface`
- `apk_entry_trace`（导出入口 → handler / input / sink / source→sink flow 证据）
- `apk_strings`
- `apk_anti_detect`
- `apk_callgraph`
- `apk_generate_hooks`（anti-detect / crypto / Firebase / entry_trace flow → Frida hooks）
- `apk_runtime_plan`（entry_trace flow / ADB replay / generated hooks → 动态验证计划）
- `apk_reverse_plan` / `apk_reverse_validate`（结构化逆向计划、优先级排序与 runtime 验证缺口回标）
- `apk_evidence_package`（runtime_plan / runtime_evidence / verified_flows → workspace Markdown/JSON 证据包 artifacts）
- `runtime_evidence` 分析记录（Frida `[ENTRY_TRACE]` 命中持久化后会聚合进 report / triage）
- `frida_*`
- `file_read`
- `code_search`

## 项目结构

```text
backend-go/
├── cmd/server/
├── configs/
├── internal/
│   ├── agent/
│   ├── analyzer/
│   ├── config/
│   ├── frida/
│   ├── handler/
│   ├── llm/
│   ├── market/
│   ├── mcp/
│   ├── model/
│   ├── runner/
│   ├── sandbox/
│   ├── server/
│   ├── store/
│   └── util/
└── data/
```

## 说明

- 当前推荐使用项目根目录 `start.sh` 统一启动整套系统
- `backend-go/Dockerfile` 可用于后端容器化；根目录 `Dockerfile` / `docker-compose.yml` 已更新为整套 Go + Flutter Web 部署骨架。
