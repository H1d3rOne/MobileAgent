# MobileAgent — 设计与实施计划

> 范围：把后端 chat 占位符升级为真正的 **Agent**（系统提示词 + 工具调用循环 + 记忆 + MCP），并把 **Termux 终端能力** 整合进 Android 端，使本应用同时支持桌面端（Web/macOS/Windows/Linux）和移动端（Android）。

---

## 1. 运行拓扑（多端）

```
                 ┌──────────────────────────────┐
                 │  Flutter Frontend (单一代码) │
                 │  Web │ macOS │ Win │ Linux  │
                 │       │ Android │ iOS       │
                 └──────────────┬───────────────┘
                                │ HTTP + SSE + WS
                                ▼
                 ┌──────────────────────────────┐
                 │   Go Backend (mobileagent)   │
                 │   - Agent loop (LLM + tools) │
                 │   - Skills registry          │
                 │   - Memory store (SQLite)    │
                 │   - MCP client (stdio)       │
                 │   - ADB runner / APK runner  │
                 └──────────────┬───────────────┘
                                │
        ┌───────────────────────┼────────────────────────┐
        ▼                       ▼                        ▼
   外部 Android 设备        本机 / Termux            MCP 服务进程
    (USB/WiFi adb)         (local shell, fs)        (stdio JSON-RPC)
```

**部署形态**：
1. **桌面**：Go 后端在 PC 启动，Flutter Desktop/Web 连接 `localhost:8320`，控制通过 USB/WiFi 连接的 Android 设备。
2. **移动**：用户在手机的 Termux 里运行 Go 后端二进制，Flutter Android App 连接 `127.0.0.1:8320`，**Agent 通过 `local_shell` skill 直接操控本机**（手机即被控目标）。
3. **混合**：Flutter Android App 连接远程后端，遇到本机操作时通过 Method Channel + Termux 桥接到本机 shell。

---

## 2. Agent 架构

### 2.1 Agent Loop

```
user_message
   │
   ▼
build_messages(system_prompt, memory, history, user_message)
   │
   ▼
LLM.stream(messages, tools=registered_tools)
   │
   ├─ token (text)                   → SSE event: token
   ├─ tool_call(id, name, args)      → SSE event: tool_call
   │     │
   │     ▼
   │   execute_tool(name, args)      → 内置 skill / MCP 工具
   │     │
   │     ▼
   │   tool_result(id, content)      → SSE event: tool_result
   │     │
   │     ▼
   │   把 tool_result 追加到 messages，回到 LLM.stream
   │
   └─ stop / finish_reason="stop"    → SSE event: done
```

每次 user 消息后，Agent 可能进行 N 轮（≤ MAX_ITER）"LLM ↔ tools" 循环，最终输出。

### 2.2 System Prompt 模板

```
You are MobileAgent, an AI assistant specialized in Android device management
and APK analysis. You operate via tool calls.

# Capabilities
- Control connected Android devices via ADB (shell, screenshot, packages, ...).
- Run local shell commands (Termux on Android, native shell on desktop).
- Analyze APK files: decompile, manifest, permissions.
- Read/write/list files in the workspace.
- Save and recall long-term memory across sessions.

# Environment
- Backend host: {host_os} {host_arch}
- Connected devices: {device_list_summary}
- Selected device: {selected_device_or_"none"}
- Workspace: {workspace_dir}
- Available tools: {tool_names_csv}

# Memory snippets
{relevant_memory_notes}

# Rules
1. Prefer one tool call per turn; reason briefly between calls.
2. If a command may modify the device or user data, ask for confirmation
   unless the user pre-authorized.
3. Cite file paths as `path:line` when referencing code locations.
4. End answers with a one-line summary of what was done or found.
```

`{...}` 字段在每次构建消息时由 `internal/agent/prompt.go` 动态填充。

### 2.3 数据流（SSE 事件协议）

后端 → 前端事件类型（在现有基础上扩展）：

| event       | data 结构                                                  | 何时发送            |
|-------------|------------------------------------------------------------|---------------------|
| `meta`      | `{"conversation_id": "..."}`                               | 流开始              |
| `token`     | `{"content": "..."}`                                       | 每个文本 delta      |
| `tool_call` | `{"id": "...", "name": "...", "arguments": {...}}`         | LLM 决定调用工具    |
| `tool_result` | `{"id": "...", "content": "...", "error": null}`        | 工具执行完成        |
| `error`     | `{"content": "..."}`                                       | 上游错误            |
| `done`      | `{"conversation_id": "..."}`                               | 全部完成            |

---

## 3. Skills 系统

### 3.1 注册方式

```go
type Skill struct {
    Name        string
    Description string
    Parameters  map[string]any   // JSON Schema
    Run         func(ctx context.Context, args map[string]any) (string, error)
}

type Registry struct { skills map[string]Skill }
func (r *Registry) Register(s Skill)
func (r *Registry) ListOpenAITools() []map[string]any
func (r *Registry) Call(ctx, name, args) (string, error)
```

### 3.2 内置 Skills（首批）

| Skill                   | 描述                               | 实现路径                       |
|-------------------------|------------------------------------|-------------------------------|
| `device_list`           | 列出所有已连 Android 设备          | `ADBRunner.ListDevices`       |
| `device_shell`          | 在指定设备上执行 adb shell         | `ADBRunner.Shell`             |
| `device_screenshot`     | 截图并返回本地路径                 | `ADBRunner.Screenshot`        |
| `device_packages`       | 列出设备已安装包                   | `ADBRunner.Shell pm list`     |
| `device_install_apk`    | 安装本地 APK 到设备                | `APKRunner.InstallToDevice`   |
| `apk_analyze`           | 解析 APK 包名/版本/权限            | `APKRunner.Analyze` + manifest|
| `apk_decompile`         | apktool/jadx 反编译                | `APKRunner.Decompile`         |
| `file_read`             | 读 workspace/uploads 下文件        | `os.ReadFile`（路径白名单）   |
| `file_write`            | 写 workspace 下文件                | `os.WriteFile`                |
| `file_list`             | 列目录                             | `os.ReadDir`                  |
| `local_shell`           | 在后端宿主机执行 shell（受限）     | `os/exec` + 超时              |
| `termux_shell`          | 当后端运行于 Termux 时，等同 local_shell；否则返回不可用 | 同上 + 环境探测 |
| `memory_save`           | 写入长期记忆                       | `MemoryStore.Save`            |
| `memory_recall`         | 按关键字检索记忆                   | `MemoryStore.Search` (LIKE)   |

### 3.3 安全护栏

- `file_*` skill 路径必须在 `cfg.Storage.WorkspaceDir` 或 `UploadDir` 之内（`filepath.Rel` 校验）。
- `local_shell`/`termux_shell`：默认 30 秒超时；可配置允许命令前缀白名单（`cfg.Skills.ShellAllowList`）；总输出截断到 64 KB。
- `device_shell`：同样的 30 秒超时与 64 KB 截断。

---

## 4. 记忆系统

### 4.1 短期（Conversation Memory）

复用现有 `AgentAction`：每条 `user_message` / `assistant_message` / `tool_call` / `tool_result` 是一行。Agent 构建 messages 时按时间顺序读取，token 估算后做截断（保留最近 N 条 + 系统提示词）。

### 4.2 长期（Notes / Facts）

新表 `agent_memory`：

```go
type AgentMemory struct {
    ID        string    `gorm:"primaryKey"`
    Scope     string    // "global" | "session:<id>" | "device:<serial>"
    Key       string    `gorm:"index"`
    Value     string    `gorm:"type:text"`
    Tags      string    // CSV
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

写入：`memory_save(scope, key, value, tags)`；
检索：`memory_recall(scope?, query, limit?)`，LIKE 匹配 key/value/tags（V1 不做 embedding）。

构建 system prompt 时，自动从 `scope="global"` 和当前 session/device 的 scope 拉取 top-K（默认 5）相关 notes 注入 `{relevant_memory_notes}`。

---

## 5. MCP 集成

### 5.1 配置（`config.yaml`）

```yaml
mcp:
  servers:
    filesystem:
      command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
      env: {}
    fetch:
      command: ["uvx", "mcp-server-fetch"]
```

### 5.2 实现

- `internal/mcp/client.go`：单 MCP server 的 stdio JSON-RPC 客户端，支持 `initialize`、`tools/list`、`tools/call`。
- `internal/mcp/manager.go`：进程生命周期管理，启动时拉起所有 server，注册它们的 tools 到 skills.Registry（以 `mcp:<server>:<tool>` 命名）。
- 进程退出时自动重启（指数退避）。

---

## 6. Termux 集成（Android 端）

### 6.1 两条路径

**路径 A — 后端跑在 Termux 内（推荐，主线）**：
1. 用户在手机上安装 Termux，`pkg install golang`，`go install ./cmd/server` 或下载预编译二进制。
2. Termux 里启动 `mobileagent-server`，监听 127.0.0.1:8320。
3. Flutter Android App 配置 `baseUrl=http://127.0.0.1:8320`，Agent 的 `local_shell`/`termux_shell` 直接是 Termux 环境。
4. 不需要 Flutter ↔ Termux 跨进程桥接，最简洁。

**路径 B — Flutter App 桥接 Termux**（补充，用于"App 单独使用"）：
1. Flutter Android 通过 `MethodChannel("io.mobileagent/termux")` 调 Kotlin 侧。
2. Kotlin 通过 Termux 的 `RUN_COMMAND` Intent 执行命令：
   ```kotlin
   val intent = Intent("com.termux.RUN_COMMAND")
       .setClassName("com.termux", "com.termux.app.RunCommandService")
       .putExtra("com.termux.RUN_COMMAND_PATH", "/data/data/com.termux/files/usr/bin/bash")
       .putExtra("com.termux.RUN_COMMAND_ARGUMENTS", arrayOf("-c", cmd))
       .putExtra("com.termux.RUN_COMMAND_BACKGROUND", true)
   ```
3. 通过 `BroadcastReceiver` 接收回调，stdout/stderr/exit 通过 EventChannel 流回 Dart。
4. Dart 暴露 `TermuxClient.exec(cmd) → Stream<TermuxOutput>`，可被 App 内"本机终端"页直接使用。
5. **前置条件**：用户的 Termux 里 `~/.termux/termux.properties` 设 `allow-external-apps=true`，并安装 Termux:API 与给本 App 授予 `com.termux.permission.RUN_COMMAND`。

### 6.2 需要补全的 Android 工程文件

当前 `frontend/android/` 只有 `local.properties` 与一个空的 `GeneratedPluginRegistrant.java`，缺：
- `android/build.gradle` / `android/app/build.gradle`
- `android/app/src/main/AndroidManifest.xml`
- `android/app/src/main/kotlin/com/mobileagent/MainActivity.kt`
- `android/app/src/main/kotlin/com/mobileagent/TermuxBridge.kt`
- 资源文件、签名配置等

由 `flutter create . --platforms=android --org com.mobileagent` 一键生成骨架，再手动注入 Termux 桥接代码与权限声明。

### 6.3 Flutter 侧（lib/core/services/termux_service.dart）

```dart
class TermuxService {
  static const _ch = MethodChannel('io.mobileagent/termux');
  static const _ev = EventChannel('io.mobileagent/termux/events');
  Future<bool> isAvailable();
  Stream<TermuxOutput> exec(String cmd);
}
```

### 6.4 新增 UI

`features/terminal/terminal_page.dart`：仅在 Android 显示的"本机终端"页，提供命令输入框 + 输出滚动区，底层是 `TermuxService`。Tab 路由 `/terminal`。

---

## 7. 数据模型增量

```diff
 store.NewStore: AutoMigrate(
     &model.Device, &model.APK, &model.APKAnalysis,
     &model.AgentSession, &model.AgentAction,
+    &model.AgentMemory,
+    &model.MCPServer,        // 持久化 MCP 服务器配置（可选，先用 yaml）
 )
```

`AgentAction` 新增字段：
```go
type AgentAction struct {
    ...
    ToolCallID   string `json:"tool_call_id,omitempty"`   // 关联 LLM 给的 id
    ToolName     string `json:"tool_name,omitempty"`
    ToolArgsJSON string `json:"tool_args,omitempty" gorm:"type:text"`
}
```

---

## 8. API 增量

| 方法 | 路径                        | 说明                                  |
|------|-----------------------------|--------------------------------------|
| GET  | `/api/v1/skills`            | （已有）列出所有 skills + JSON Schema |
| GET  | `/api/v1/mcp/servers`       | 列出已加载的 MCP server 与状态       |
| POST | `/api/v1/mcp/servers/:name/restart` | 重启某个 MCP server          |
| GET  | `/api/v1/memory`            | `?scope=&q=` 搜记忆                  |
| POST | `/api/v1/memory`            | 写入 1 条记忆                        |
| DELETE | `/api/v1/memory/:id`      | 删除记忆                              |

---

## 9. 前端改造

1. **SSE 修复**：`api_service.dart` 在 Web 用 `package:web`/`dart:html` 的 `XMLHttpRequest` + `onProgress` 事件实现真正流式读取；非 Web 保留现 dio 流。
2. **Tool Call 渲染**：`chat_provider.dart` 已有 `tool_call`/`tool_result` 分支，补 UI（`ChatPage._buildToolCallChip` 已有雏形，扩展为可展开查看 args/result）。
3. **新页面**（路由）：
   - `/memory` —— 列出/搜索/删除长期记忆
   - `/mcp` —— MCP 服务器状态
   - `/terminal` —— Android-only Termux 终端（路径 B）
4. **Sidebar** 增加对应入口。

---

## 10. 配置增量（`configs/config.yaml`）

```yaml
agent:
  max_iterations: 10            # tool 循环上限
  history_max_messages: 40      # 进 LLM 的最大历史条数
  memory_recall_top_k: 5        # 注入 system prompt 的 notes 数

skills:
  shell_timeout_seconds: 30
  shell_max_output_bytes: 65536
  shell_allow_prefixes: []      # 空 = 不限制；建议生产环境收紧

mcp:
  servers: {}                   # 见 §5.1
```

---

## 11. 实施分期

- **P0（本次）**：
  - 后端 Agent loop（带 tool-calling）+ SystemPrompt + 5 个内置 skills（`device_list`、`device_shell`、`device_screenshot`、`apk_analyze`、`local_shell`）
  - `agent_memory` 表 + `memory_save`/`memory_recall` skill + 系统提示词注入
  - MCP stdio 客户端 + 配置加载
  - 前端：SSE 修复 + tool_call/tool_result 气泡渲染
- **P1（后续）**：
  - Android 工程脚手架（`flutter create`）+ Termux MethodChannel + `/terminal` 页
  - 剩余 skills（`apk_decompile`、`file_*`、`device_packages` 等）
  - 记忆/MCP 管理页面
- **P2**：embedding 检索版长期记忆、tool 调用并行化、可视化工具流。

> 本次 commit 落地 **P0**。Android 脚手架与 Termux 桥接代码本次随 `frontend/android/` 文件一并加入，但 P0 不要求一定要在真机跑通——MainActivity/Manifest/MethodChannel 三件套就位即可，具体 `flutter pub get`/`gradle sync` 留给开发者本地完成。
