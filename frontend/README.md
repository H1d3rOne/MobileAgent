# MobileAgent Frontend

Flutter 前端，负责提供统一的 Agent / APK / Device / MCP 工作台。

## 当前页面

- Chat
- APK
- Devices
- Skills
- Memory
- MCP
- Terminal
- Settings

## 技术栈

- Flutter
- Riverpod
- GoRouter
- Dio

## 启动

开发模式：

```bash
flutter run -d chrome --web-port 9999
```

静态构建：

```bash
flutter build web --release --no-web-resources-cdn
```

测试与检查：

```bash
flutter analyze
flutter test
```

## APK 工作台能力

- APK 上传
- 反编译（apktool / jadx）
- Manifest / Certificate / Risk / Attack Surface / Entry Trace / Packer / Code / SDK / Strings / Anti-Detection
- Agent Triage 专用视图
- Attack Surface 视图：导出组件、deeplink/app link、content provider、ADB replay commands
- Entry Trace 视图：导出入口 handler、外部输入、sink 证据、method-local source→sink flow evidence、ADB replay commands
- Report / Hooks / Runtime Plan / Call Graph / Diff；Hooks 会结合 anti-detect、crypto、Firebase 和 Entry Trace source→sink flows 生成带 `flow_id` 的 Frida monitor，并可从前端直接运行生成脚本；Runtime Plan 可把 hooks、ADB replay commands 和验证步骤串成不触设备的动态验证计划，Frida 运行输出会解析 `[ENTRY_TRACE][...][flows=flow-001]` runtime evidence、精确回标 flow，并保存为 APK `runtime_evidence`；Report / Triage 会展示“静态 flow + 动态命中”的证据链，Report 面板可复制 Evidence Package Markdown
- Build / Sign / Install
- Native / Components / Network 工具页

## 已知问题

- Android 原生工程骨架已生成并接入 `TermuxBridge`，但本机 Gradle 分发包下载未收口；如需验证原生侧，请在网络可用环境运行 `cd android && ./gradlew :app:compileDebugKotlin`。
