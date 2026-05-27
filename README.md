# 🤖 MobileAgent

面向安卓安全分析与逆向工程的 Agent 平台。

当前实现已经从早期原型演进为：

- **后端**：Go / Gin / GORM / SQLite
- **前端**：Flutter / Riverpod / GoRouter
- **核心方向**：让 Agent 具备类似 Claude Code / Codex 的工具调用能力，并把能力聚焦到 APK 静态分析、设备控制、Frida 动态分析、MCP 扩展和安卓逆向工作流。

---

## 当前能力

### Agent 能力

- Chat-based Agent，会话与历史持久化
- Tool calling：设备、文件、Shell、Frida、APK 分析、记忆、MCP 工具
- 危险工具审批模式：
  - `deny`
  - `approval`
  - `yolo`
- 持久化记忆（session / global / device scope）
- 外部 skill pack / MCP 扩展接入

### 安卓逆向能力

- APK 上传与基础分析
- `apktool` / `jadx` 反编译
- Manifest / Certificate / Risk / Attack Surface / Entry Trace / Code / SDK / Strings / Anti-detect / Packer 分析
- Entry Trace 已支持 method-local `source→sink` flow evidence，能把导出入口、外部输入、危险 sink 和变量传播链串起来
- **Agent Triage**：
  - `apk_triage` skill / `apk_reverse_plan` / `apk_reverse_validate`
  - `POST /api/v1/apk/:id/analyze/triage`
  - 自动聚合 manifest、certificate、risk、attack_surface、entry_trace、packer、code、sdk、strings、anti-detect、callgraph、hook suggestions、next steps
  - `entry_trace` 会汇总 handler / input / sink / `source→sink` flow 证据，帮助 Agent 缩小后续阅读与动态验证范围
- Frida 脚本管理、hook 生成、spawn / attach / run script；`apk_generate_hooks` 会结合 anti-detect、crypto、Firebase 与 Entry Trace `source→sink` flows 生成带 `flow_id` 的针对性监控脚本，`apk_runtime_plan` 会把 flows、ADB replay commands、生成脚本与 ready-to-run `frida_hook` 参数整理成动态验证计划，前端 Hooks / Runtime Plan 面板可直接运行生成脚本、解析 `[ENTRY_TRACE][...][flows=flow-001]` runtime evidence，精确回标 flow，并持久化为 APK `runtime_evidence` 分析记录；Report / Triage 会把已保存动态命中与 Runtime Plan 静态 flow 详情合并成证据链，Evidence Package 可一键导出 Markdown/JSON 证据包；新增 `apk_reverse_plan` 生成结构化逆向计划与验证清单，`apk_reverse_validate` 用 runtime evidence 回标验证状态
- Call graph / report / APK diff / network capture parsing

### 设备与环境能力

- ADB 设备发现、连接、shell、截图、包列表、安装 APK
- 终端工具面板（radare2 / androguard / mitmproxy）
- Web UI 中的 APK 工作台、聊天、技能、MCP、记忆、设置页面

---

## 项目结构

```text
MobileAgent/
├── backend-go/                 # Go 后端
│   ├── cmd/server/             # 服务入口
│   ├── configs/config.yaml     # 主配置
│   ├── internal/
│   │   ├── agent/              # Agent loop / prompt / skills
│   │   ├── analyzer/           # APK/逆向分析器
│   │   ├── handler/            # HTTP handlers
│   │   ├── runner/             # adb/apk/frida 执行器
│   │   ├── server/             # 路由与服务装配
│   │   └── store/              # SQLite / GORM 存储
│   └── data/                   # 运行时数据库与工作区
├── frontend/                   # Flutter 前端
│   └── lib/
│       ├── core/               # models/providers/services
│       ├── features/           # chat/apk/device/mcp/skills/...
│       └── shared/
├── tools/                      # 工具安装脚本与二进制目录
├── start.sh                    # 一键启动脚本
└── PLAN.md                     # 设计与实施计划
```

---

## 快速启动

### 依赖

- Go 1.22+
- Flutter 3.x / Dart 3.x
- Java（用于 apktool / jadx / apksigner 等）
- Android 平台工具（ADB）

如果使用项目自带工具链，先执行：

```bash
bash tools/setup.sh
```

### 方式 1：一键启动

项目根目录提供启动脚本：

```bash
./start.sh start
```

默认行为：

- 后端监听：`http://localhost:8320`
- 前端构建 Flutter Web 后以静态服务运行：`http://localhost:9999`

停止：

```bash
./start.sh stop
```

### 方式 2：分别启动

后端：

```bash
cd backend-go
go build -o build/mobileagent-server ./cmd/server
./build/mobileagent-server -config configs/config.yaml
```

前端（开发模式）：

```bash
cd frontend
flutter run -d chrome --web-port 9999
```

前端（静态构建）：

```bash
cd frontend
flutter build web --release --no-web-resources-cdn
```

---

## 关键 API

### Chat / Agent

- `POST /api/v1/chat`
- `POST /api/v1/chat/approve`
- `GET /api/v1/conversations`
- `GET /api/v1/conversations/:id`
- `POST /api/v1/conversations/:id/rollback`

### APK / Reverse Engineering

- `POST /api/v1/apk/analyze`
- `POST /api/v1/apk/decompile`
- `POST /api/v1/apk/build`
- `POST /api/v1/apk/sign`
- `POST /api/v1/apk/install`
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
- `POST /api/v1/apk/:id/runtime_plan`
- `GET /api/v1/apk/:id/report`
- `GET /api/v1/apk/:id/evidence_package`
- `GET /api/v1/apk/:id/hooks`
- `GET /api/v1/apk/:id/callgraph`
- `GET /api/v1/apk/diff`

### Devices / Frida / MCP

- `GET /api/v1/devices`
- `POST /api/v1/devices/:serial/shell`
- `POST /api/v1/devices/:serial/screenshot`
- `POST /api/v1/devices/:serial/connect`
- `GET /api/v1/frida/scripts`
- `POST /api/v1/frida/run`
- `GET /api/v1/mcp/tools`
- `GET /api/v1/skills`

---

## Agent 逆向工作流

当前推荐的 APK 逆向 Agent 路径：

1. `apk_list`
2. `apk_triage`
3. 若未反编译：`apk_decompile`
4. 重新 `apk_triage`
5. 根据 `next_steps` 进入：
   - `apk_attack_surface` + `apk_entry_trace`
   - `code_search` + `file_read`
   - `apk_callgraph`
   - `apk_generate_hooks`（可把 Entry Trace flow 转成 entry-trace Frida monitor）
   - `apk_runtime_plan`（生成不触设备的动态验证执行计划与 ready-to-run Frida 参数）
   - `apk_evidence_package`（导出最终 Markdown/JSON 证据包 artifacts）
   - `frida_*` 动态分析工具

前端 APK 页面也提供了相同能力：

- Triage
- Attack Surface / Entry Trace（含 source→sink flow evidence）
- Packer
- Strings
- Protection
- Hooks（生成、复制、直接运行 Frida hook）
- Runtime Plan（不触设备地生成 ADB replay、Frida hook 参数和验证步骤）
- Call Graph
- Report

---

## 配置

主配置文件：

```text
backend-go/configs/config.yaml
```

重点配置项：

- `server`：监听地址、端口、CORS
- `adb`：ADB 路径、自动连接
- `llm`：模型、API Key、Base URL、API 类型
- `tools`：`apktool` / `jadx` / `apksigner` / `zipalign` / `uber-apk-signer` / `r2` / `androguard` / `mitmproxy`
- `storage`：数据库、上传目录、工作区、记忆目录
- `agent`：最大迭代、历史条数、记忆召回、审批模式
- `sandbox`：命令白名单

---

## 验证命令

后端：

```bash
cd backend-go
go test ./...
go build ./cmd/server
```

前端：

```bash
cd frontend
flutter analyze
flutter test
```

---

## 当前已知限制 / 待改进

- Android 原生工程骨架已生成，并接回 `TermuxBridge`；本机 `./gradlew :app:compileDebugKotlin` 验证因 Gradle 分发包下载长时间未完成，仍需在网络可用环境下复跑。
- 根目录 `Dockerfile` / `docker-compose.yml` 已更新为 Go + Flutter Web 架构；本机缺少 `docker` 命令，容器构建仍需在 Docker 环境复验。
- 后端分析器与 handler 的自动化测试覆盖还不够高，尤其是 triage / sign / packer / strings / anti-detect 组合路径

---

## 参考文档

- 后端说明：`backend-go/README.md`
- 前端说明：`frontend/README.md`
- 设计计划：`PLAN.md`
