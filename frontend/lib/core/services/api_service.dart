import 'dart:async';
import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'sse_web_stub.dart' if (dart.library.html) 'sse_web_html.dart';

/// A single LLM provider profile.
class LLMProvider {
  final String id;
  final String name;
  final String apiKey;
  final String baseUrl;
  final String model;
  final String apiType;

  LLMProvider({
    required this.id,
    this.name = '',
    this.apiKey = '',
    this.baseUrl = '',
    this.model = '',
    this.apiType = 'chat_completions',
  });

  LLMProvider copyWith({
    String? id,
    String? name,
    String? apiKey,
    String? baseUrl,
    String? model,
    String? apiType,
  }) =>
      LLMProvider(
        id: id ?? this.id,
        name: name ?? this.name,
        apiKey: apiKey ?? this.apiKey,
        baseUrl: baseUrl ?? this.baseUrl,
        model: model ?? this.model,
        apiType: apiType ?? this.apiType,
      );

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'apiKey': apiKey,
        'baseUrl': baseUrl,
        'model': model,
        'apiType': apiType,
      };

  factory LLMProvider.fromJson(Map<String, dynamic> json) => LLMProvider(
        id: json['id'] ?? DateTime.now().millisecondsSinceEpoch.toString(),
        name: json['name'] ?? '',
        apiKey: json['apiKey'] ?? '',
        baseUrl: json['baseUrl'] ?? '',
        model: json['model'] ?? '',
        apiType: json['apiType'] ?? 'chat_completions',
      );
}

/// API configuration provider
final apiConfigProvider = StateNotifierProvider<ApiConfigNotifier, ApiConfig>(
  (ref) => ApiConfigNotifier(),
);

class ApiConfig {
  final String backendUrl;
  final List<LLMProvider> providers;
  final String activeProviderId;
  final String adbPath;
  final String approvalMode;

  ApiConfig({
    this.backendUrl = 'http://localhost:8320',
    this.providers = const [],
    this.activeProviderId = '',
    this.adbPath = 'adb',
    this.approvalMode = 'approval',
  });

  LLMProvider? get activeProvider {
    if (providers.isEmpty) return null;
    final idx = providers.indexWhere((p) => p.id == activeProviderId);
    return idx != -1 ? providers[idx] : providers.first;
  }

  // Legacy compatibility getters
  String get baseUrl => backendUrl;
  String get provider => activeProvider?.name ?? 'openai';
  String get apiKey => activeProvider?.apiKey ?? '';
  String get llmBaseUrl => activeProvider?.baseUrl ?? '';
  String get model => activeProvider?.model ?? 'gpt-4o';
  String get apiType => activeProvider?.apiType ?? 'chat_completions';

  ApiConfig copyWith({
    String? backendUrl,
    List<LLMProvider>? providers,
    String? activeProviderId,
    String? adbPath,
    String? approvalMode,
  }) =>
      ApiConfig(
        backendUrl: backendUrl ?? this.backendUrl,
        providers: providers ?? this.providers,
        activeProviderId: activeProviderId ?? this.activeProviderId,
        adbPath: adbPath ?? this.adbPath,
        approvalMode: approvalMode ?? this.approvalMode,
      );

  Map<String, dynamic> toJson() => {
        'backendUrl': backendUrl,
        'providers': providers.map((p) => p.toJson()).toList(),
        'activeProviderId': activeProviderId,
        'adbPath': adbPath,
        'approvalMode': approvalMode,
      };

  factory ApiConfig.fromJson(Map<String, dynamic> json) {
    final providersList = (json['providers'] as List?)
            ?.map((p) => LLMProvider.fromJson(p as Map<String, dynamic>))
            .toList() ??
        [];
    return ApiConfig(
      backendUrl:
          json['backendUrl'] ?? json['baseUrl'] ?? 'http://localhost:8320',
      providers: providersList,
      activeProviderId: json['activeProviderId'] ?? '',
      adbPath: json['adbPath'] ?? 'adb',
      approvalMode: json['approvalMode'] ?? 'approval',
    );
  }
}

class ApiConfigNotifier extends StateNotifier<ApiConfig> {
  ApiConfigNotifier() : super(ApiConfig()) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    final jsonString = prefs.getString('app_config_v2');
    if (jsonString != null && jsonString.isNotEmpty) {
      try {
        final json = jsonDecode(jsonString);
        state = ApiConfig.fromJson(json);
        return;
      } catch (_) {}
    }

    // Migrate from v1 config
    final v1String = prefs.getString('app_config');
    if (v1String != null && v1String.isNotEmpty) {
      try {
        final v1 = jsonDecode(v1String);
        final migrated = ApiConfig(
          backendUrl: v1['baseUrl'] ?? 'http://localhost:8320',
          providers: [
            LLMProvider(
              id: '1',
              name: v1['provider'] ?? 'openai',
              apiKey: v1['apiKey'] ?? '',
              baseUrl: v1['llmBaseUrl'] ?? '',
              model: v1['model'] ?? 'gpt-4o',
              apiType: v1['apiType'] ?? 'chat_completions',
            ),
          ],
          activeProviderId: '1',
          adbPath: v1['adbPath'] ?? 'adb',
          approvalMode: v1['approvalMode'] ?? 'approval',
        );
        state = migrated;
        await _save();
        return;
      } catch (_) {}
    }

    // Migrate from legacy keys
    final hasLegacy = prefs.containsKey('llm_provider') ||
        prefs.containsKey('llm_api_key') ||
        prefs.containsKey('llm_base_url') ||
        prefs.containsKey('llm_model');

    if (hasLegacy) {
      final migrated = ApiConfig(
        backendUrl: 'http://localhost:8320',
        providers: [
          LLMProvider(
            id: '1',
            name: prefs.getString('llm_provider') ?? 'openai',
            apiKey: prefs.getString('llm_api_key') ?? '',
            baseUrl: prefs.getString('llm_base_url') ?? '',
            model: prefs.getString('llm_model') ?? 'gpt-4o',
            apiType: prefs.getString('llm_api_type') ?? 'chat_completions',
          ),
        ],
        activeProviderId: '1',
        adbPath: prefs.getString('llm_adb_path') ?? 'adb',
        approvalMode: 'approval',
      );
      state = migrated;
      await _save();
      await prefs.remove('llm_provider');
      await prefs.remove('llm_api_key');
      await prefs.remove('llm_base_url');
      await prefs.remove('llm_model');
      await prefs.remove('llm_api_type');
      await prefs.remove('llm_adb_path');
      return;
    }

    state = ApiConfig();
  }

  Future<void> _save() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('app_config_v2', jsonEncode(state.toJson()));
  }

  Future<void> update(ApiConfig config) async {
    state = config;
    await _save();
  }

  Future<void> addProvider(LLMProvider provider) async {
    final updated = state.copyWith(
      providers: [...state.providers, provider],
      activeProviderId:
          state.providers.isEmpty ? provider.id : state.activeProviderId,
    );
    state = updated;
    await _save();
  }

  Future<void> updateProvider(LLMProvider provider) async {
    final providers =
        state.providers.map((p) => p.id == provider.id ? provider : p).toList();
    state = state.copyWith(providers: providers);
    await _save();
  }

  Future<void> removeProvider(String id) async {
    final providers = state.providers.where((p) => p.id != id).toList();
    var activeId = state.activeProviderId;
    if (activeId == id) {
      activeId = providers.isNotEmpty ? providers.first.id : '';
    }
    state = state.copyWith(providers: providers, activeProviderId: activeId);
    await _save();
  }

  Future<void> setActiveProvider(String id) async {
    state = state.copyWith(activeProviderId: id);
    await _save();
  }
}

class ApiService {
  late final Dio _dio;
  final ApiConfig config;

  ApiService(this.config) {
    _dio = Dio(
      BaseOptions(
        baseUrl: '${config.baseUrl}/api/v1',
        connectTimeout: const Duration(seconds: 10),
        receiveTimeout: const Duration(seconds: 300),
        headers: {'Content-Type': 'application/json'},
      ),
    );
    _dio.interceptors
        .add(LogInterceptor(requestBody: true, responseBody: false));
  }

  dynamic _data(Response res) => res.data['data'];

  Stream<ChatStreamEvent> streamChat(String sessionId, String message,
      {List<String>? attachmentPaths}) async* {
    if (kIsWeb) {
      yield* _streamChatWeb(sessionId, message,
          attachmentPaths: attachmentPaths);
    } else {
      yield* _streamChatNative(sessionId, message,
          attachmentPaths: attachmentPaths);
    }
  }

  Map<String, dynamic> _buildChatData(String sessionId, String message,
      {List<String>? attachmentPaths}) {
    return {
      'conversation_id': sessionId,
      'message': message,
      'attachments': attachmentPaths,
      'llm': {
        'provider': config.provider,
        'api_key': config.apiKey,
        'base_url': config.llmBaseUrl,
        'model': config.model,
        'api_type': config.apiType,
      },
    };
  }

  Stream<ChatStreamEvent> _streamChatNative(String sessionId, String message,
      {List<String>? attachmentPaths}) async* {
    final response = await _dio.post<ResponseBody>(
      '/chat',
      data:
          _buildChatData(sessionId, message, attachmentPaths: attachmentPaths),
      options: Options(
        responseType: ResponseType.stream,
        headers: {'Accept': 'text/event-stream'},
      ),
    );

    String buffer = '';
    String currentEventType = 'message';
    await for (final chunk in response.data!.stream) {
      buffer += utf8.decode(chunk, allowMalformed: true);
      while (buffer.contains('\n')) {
        final idx = buffer.indexOf('\n');
        final line = buffer.substring(0, idx).trim();
        buffer = buffer.substring(idx + 1);
        if (line.startsWith('event: ')) {
          currentEventType = line.substring(7).trim();
        } else if (line.startsWith('data: ')) {
          yield* _parseSSELine(line, currentEventType);
          currentEventType = 'message';
        } else if (line.isEmpty) {
          currentEventType = 'message';
        }
      }
    }
    if (buffer.trim().isNotEmpty && buffer.trim().startsWith('data: ')) {
      yield* _parseSSELine(buffer.trim(), currentEventType);
    }
  }

  Stream<ChatStreamEvent> _streamChatWeb(String sessionId, String message,
      {List<String>? attachmentPaths}) async* {
    final url = '${config.baseUrl}/api/v1/chat';
    final body = jsonEncode(
        _buildChatData(sessionId, message, attachmentPaths: attachmentPaths));
    final stream = webSseStream(
      url: url,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
      },
      body: body,
    );

    int processed = 0;
    String buffer = '';
    String currentEventType = 'message';

    await for (final cumulative in stream) {
      if (cumulative.length <= processed) continue;
      final delta = cumulative.substring(processed);
      processed = cumulative.length;
      buffer += delta;
      while (buffer.contains('\n')) {
        final idx = buffer.indexOf('\n');
        final line = buffer.substring(0, idx);
        buffer = buffer.substring(idx + 1);
        final trimmed = line.trim();
        if (trimmed.startsWith('event: ')) {
          currentEventType = trimmed.substring(7).trim();
        } else if (trimmed.startsWith('data: ')) {
          yield* _parseSSELine(trimmed, currentEventType);
          currentEventType = 'message';
        } else if (trimmed.isEmpty) {
          currentEventType = 'message';
        }
      }
    }
    if (buffer.trim().isNotEmpty && buffer.trim().startsWith('data: ')) {
      yield* _parseSSELine(buffer.trim(), currentEventType);
    }
  }

  Stream<ChatStreamEvent> _parseSSELine(String line, String eventType) async* {
    if (!line.startsWith('data: ')) return;
    final data = line.substring(6);
    if (data == '[DONE]') {
      yield ChatStreamEvent(type: 'done');
      return;
    }
    if (eventType == 'done') {
      yield ChatStreamEvent(type: 'done');
      return;
    }
    if (eventType == 'meta') {
      try {
        final json = jsonDecode(data);
        yield ChatStreamEvent(type: 'meta', content: json['conversation_id']);
      } catch (_) {}
      return;
    }
    try {
      final json = jsonDecode(data);
      switch (eventType) {
        case 'token':
          yield ChatStreamEvent(type: 'token', content: json['content']);
          break;
        case 'tool_call':
          yield ChatStreamEvent(
            type: 'tool_call',
            toolCall: {
              'id': json['id'] ?? '',
              'name': json['name'] ?? '',
              'arguments': (json['arguments'] is Map) ? json['arguments'] : {},
            },
          );
          break;
        case 'tool_result':
          yield ChatStreamEvent(
            type: 'tool_result',
            toolResult: {
              'id': json['id'] ?? '',
              'name': json['name'] ?? '',
              'content': json['content']?.toString() ?? '',
              'error': json['error'] == true,
            },
          );
          break;
        case 'approval_request':
          yield ChatStreamEvent(
            type: 'approval_request',
            approvalRequest: {
              'id': json['id'] ?? '',
              'name': json['name'] ?? '',
              'arguments': (json['arguments'] is Map) ? json['arguments'] : {},
            },
          );
          break;
        case 'error':
          yield ChatStreamEvent(
              type: 'error', content: json['content'] ?? json['error']);
          break;
        default:
          yield ChatStreamEvent.fromJson(json);
      }
    } catch (_) {}
  }

  Future<List<Map<String, dynamic>>> listConversations() async {
    final res = await _dio.get('/conversations');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<Map<String, dynamic>> getConversation(String id) async {
    final res = await _dio.get('/conversations/$id');
    return _data(res) as Map<String, dynamic>;
  }

  Future<void> deleteConversation(String id) async {
    await _dio.delete('/conversations/$id');
  }

  Future<void> rollbackConversation(String id, String actionId) async {
    await _dio
        .post('/conversations/$id/rollback', data: {'action_id': actionId});
  }

  Future<Map<String, dynamic>> approveToolCall(
      String toolCallId, bool approved) async {
    final res = await _dio.post('/chat/approve', data: {
      'tool_call_id': toolCallId,
      'approved': approved,
    });
    return _data(res) as Map<String, dynamic>;
  }

  Future<List<Map<String, dynamic>>> listPendingApprovals(
      String conversationId) async {
    final res =
        await _dio.get('/conversations/$conversationId/pending-approvals');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<List<Map<String, dynamic>>> listDevices() async {
    final res = await _dio.get('/devices');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<Map<String, dynamic>> getDeviceInfo(String serial) async {
    final res = await _dio.get('/devices/$serial/info');
    return _data(res) as Map<String, dynamic>;
  }

  Future<String> executeShell(String serial, String command) async {
    final res =
        await _dio.post('/devices/$serial/shell', data: {'command': command});
    return _data(res)['output'] ?? '';
  }

  Future<String> takeScreenshot(String serial) async {
    final res = await _dio.post('/devices/$serial/screenshot');
    return _data(res)['path'] ?? '';
  }

  Future<Map<String, dynamic>> getBattery(String serial) async {
    final res = await _dio.get('/devices/$serial/battery');
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> listPackages(String serial,
      {String? filter}) async {
    final res =
        await _dio.post('/devices/$serial/packages', data: {'filter': filter});
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> connectWireless(
      String serial, String address) async {
    final res =
        await _dio.post('/devices/$serial/connect', data: {'address': address});
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> uploadAndAnalyze(
    String filename, {
    String? filePath,
    List<int>? bytes,
  }) async {
    MultipartFile file;
    if (bytes != null) {
      file = MultipartFile.fromBytes(bytes, filename: filename);
    } else if (filePath != null) {
      file = await MultipartFile.fromFile(filePath, filename: filename);
    } else {
      throw ArgumentError('Either filePath or bytes must be provided');
    }
    final formData = FormData.fromMap({'file': file});
    final res = await _dio.post('/apk/analyze', data: formData);
    return _data(res) as Map<String, dynamic>;
  }

  Future<List<Map<String, dynamic>>> listApks() async {
    final res = await _dio.get('/apk');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<void> deleteApk(String id) async {
    await _dio.delete('/apk/$id');
  }

  Future<Map<String, dynamic>> browseDir(String dir) async {
    final res = await _dio.get('/apk/dir', queryParameters: {'dir': dir});
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> listApkAnalyses(String id) async {
    final res = await _dio.get('/apk/$id/analyses');
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    return {};
  }

  Future<Map<String, dynamic>> runApkAnalyzer(String id, String type) async {
    final res = await _dio.post('/apk/$id/analyze/$type');
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    return {};
  }

  Future<Map<String, dynamic>> runApkTriage(String id,
      {bool includeCallgraph = false}) async {
    final res = await _dio.post('/apk/$id/analyze/triage', data: {
      'include_callgraph': includeCallgraph,
    });
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    return {};
  }

  Future<Map<String, dynamic>> decompileApk(String apkPath,
      {String tool = 'apktool', String? id}) async {
    final res = await _dio.post('/apk/decompile', data: {
      'path': apkPath,
      'tool': tool,
      if (id != null && id.isNotEmpty) 'id': id,
    });
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> browseFile(String dir, String file) async {
    final res = await _dio
        .get('/apk/file', queryParameters: {'dir': dir, 'file': file});
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> buildApk(String projectPath,
      {Map<String, dynamic>? options}) async {
    final res = await _dio.post('/apk/build', data: {
      'source_dir': projectPath,
      'project_path': projectPath,
      ...?options
    });
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> signApk(
    String apkPath, {
    String? keystorePath,
    String? keyAlias,
    String? storePass,
    String? keyPass,
  }) async {
    final res = await _dio.post('/apk/sign', data: {
      'apk_path': apkPath,
      'keystore_path': keystorePath,
      'key_alias': keyAlias,
      'store_pass': storePass,
      'key_pass': keyPass,
    });
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> installApk(String serial, String apkPath) async {
    final res = await _dio
        .post('/apk/install', data: {'serial': serial, 'apk_path': apkPath});
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> healthCheck() async {
    final res = await _dio.get('/health');
    return res.data;
  }

  Future<Map<String, dynamic>> systemStatus() async {
    final res = await _dio.get('/status');
    return _data(res) as Map<String, dynamic>;
  }

  Future<List<Map<String, dynamic>>> toolsStatus() async {
    final res = await _dio.get('/tools/status');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<Map<String, dynamic>> shellCommand(String command) async {
    final res = await _dio.post('/tools/run', data: {'command': command});
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> generateReport(String apkId) async {
    final res = await _dio.get('/apk/$apkId/report');
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> evidencePackage(String apkId) async {
    final res = await _dio.get('/apk/$apkId/evidence_package');
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    return {};
  }

  Future<Map<String, dynamic>> detectPacker(String apkId) async {
    final res = await _dio.get('/apk/$apkId/packer');
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> scanStrings(String apkId) async {
    final res = await _dio.post('/apk/$apkId/analyze/strings');
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> detectAntiDetection(String apkId) async {
    final res = await _dio.post('/apk/$apkId/analyze/antidetect');
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> generateHooks(String apkId) async {
    final res = await _dio.get('/apk/$apkId/hooks');
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    if (data is List) {
      return {
        'hooks': data.cast<Map<String, dynamic>>(),
        'count': data.length,
      };
    }
    return {'hooks': <Map<String, dynamic>>[], 'count': 0};
  }

  Future<Map<String, dynamic>> reversePlan(String apkId) async {
    final res = await _dio.post('/apk/$apkId/reverse_plan');
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    return {};
  }

  Future<Map<String, dynamic>> reverseValidate(String apkId) async {
    final res = await _dio.post('/apk/$apkId/reverse_validate');
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    return {};
  }

  Future<Map<String, dynamic>> runtimePlan(String apkId,
      {String? serial}) async {
    final res = await _dio.post('/apk/$apkId/runtime_plan', data: {
      if (serial != null && serial.isNotEmpty) 'serial': serial,
    });
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    return {};
  }

  Future<Map<String, dynamic>> callGraph(String apkId,
      {String? package_}) async {
    final params = <String, dynamic>{};
    if (package_ != null) params['package'] = package_;
    final res =
        await _dio.get('/apk/$apkId/callgraph', queryParameters: params);
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> diffAPKs(String oldId, String newId) async {
    final res = await _dio
        .get('/apk/diff', queryParameters: {'old': oldId, 'new': newId});
    return _data(res) as Map<String, dynamic>;
  }

  Future<List<Map<String, dynamic>>> listFridaScripts(
      {String? category}) async {
    final params = <String, dynamic>{};
    if (category != null) params['category'] = category;
    final res = await _dio.get('/frida/scripts', queryParameters: params);
    final data = _data(res);
    if (data is Map && data['scripts'] is List) {
      return (data['scripts'] as List).cast<Map<String, dynamic>>();
    }
    return [];
  }

  Future<Map<String, dynamic>> getFridaScript(String id) async {
    final res = await _dio.get('/frida/scripts/$id');
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> runFridaScript(
      String scriptId, String serial, String target,
      {int timeout = 30, String? apkId}) async {
    final res = await _dio.post('/frida/scripts/$scriptId/run', data: {
      'serial': serial,
      'target': target,
      'timeout': timeout,
      if (apkId != null && apkId.isNotEmpty) 'apk_id': apkId,
    });
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    if (res.data is Map) return (res.data as Map).cast<String, dynamic>();
    return {};
  }

  Future<Map<String, dynamic>> runFridaCode(
      String serial, String target, String script,
      {int timeout = 30, String? apkId, String? hookId}) async {
    final res = await _dio.post('/frida/run', data: {
      'serial': serial,
      'target': target,
      'script': script,
      'timeout': timeout,
      if (apkId != null && apkId.isNotEmpty) 'apk_id': apkId,
      if (hookId != null && hookId.isNotEmpty) 'hook_id': hookId,
    });
    final data = _data(res);
    if (data is Map) return data.cast<String, dynamic>();
    if (res.data is Map) return (res.data as Map).cast<String, dynamic>();
    return {};
  }

  Future<Map<String, dynamic>> parseNetworkCapture(
      List<int> fileBytes, String fileName) async {
    final formData = FormData.fromMap({
      'file': MultipartFile.fromBytes(fileBytes, filename: fileName),
    });
    final res = await _dio.post('/network/parse', data: formData);
    return _data(res) as Map<String, dynamic>;
  }

  Future<List<String>> listFridaCategories() async {
    final res = await _dio.get('/frida/categories');
    final data = _data(res);
    if (data is Map && data['categories'] is List) {
      return (data['categories'] as List).cast<String>();
    }
    return [];
  }

  Future<List<Map<String, dynamic>>> listSkills() async {
    final res = await _dio.get('/skills');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<List<Map<String, dynamic>>> listSkillCatalog() async {
    final res = await _dio.get('/skills/catalog');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<List<Map<String, dynamic>>> listInstalledSkills() async {
    final res = await _dio.get('/skills/installed');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<Map<String, dynamic>> installSkill(
      Map<String, dynamic> payload) async {
    final res = await _dio.post('/skills/install', data: payload);
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> enableSkill(String id) async {
    final res = await _dio.post('/skills/$id/enable');
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> disableSkill(String id) async {
    final res = await _dio.post('/skills/$id/disable');
    return _data(res) as Map<String, dynamic>;
  }

  Future<void> deleteSkill(String id) async {
    await _dio.delete('/skills/$id');
  }

  Future<List<Map<String, dynamic>>> listMemory(
      {String? query, String? scope}) async {
    final res = await _dio.get(
      '/memory',
      queryParameters: {
        if (query != null && query.isNotEmpty) 'q': query,
        if (scope != null && scope.isNotEmpty) 'scope': scope,
      },
    );
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<Map<String, dynamic>> createMemory({
    required String key,
    required String value,
    String scope = 'global',
    String tags = '',
  }) async {
    final res = await _dio.post('/memory', data: {
      'scope': scope,
      'key': key,
      'value': value,
      'tags': tags,
    });
    return _data(res) as Map<String, dynamic>;
  }

  Future<void> deleteMemory(String id) async {
    await _dio.delete('/memory/$id');
  }

  Future<List<Map<String, dynamic>>> listMcpServers() async {
    final res = await _dio.get('/mcp/servers');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<List<Map<String, dynamic>>> listMcpCatalog() async {
    final res = await _dio.get('/mcp/catalog');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<List<Map<String, dynamic>>> listInstalledMcp() async {
    final res = await _dio.get('/mcp/installed');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<Map<String, dynamic>> installMcp(Map<String, dynamic> payload,
      {bool manual = false}) async {
    final res =
        await _dio.post(manual ? '/mcp/manual' : '/mcp/install', data: payload);
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> enableMcp(String id) async {
    final res = await _dio.post('/mcp/$id/enable');
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> disableMcp(String id) async {
    final res = await _dio.post('/mcp/$id/disable');
    return _data(res) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> restartMcp(String id) async {
    final res = await _dio.post('/mcp/$id/restart');
    return _data(res) as Map<String, dynamic>;
  }

  Future<void> deleteMcp(String id) async {
    await _dio.delete('/mcp/$id');
  }

  Future<List<Map<String, dynamic>>> listMcpTools() async {
    final res = await _dio.get('/mcp/tools');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<List<Map<String, dynamic>>> listMarketSources() async {
    final res = await _dio.get('/market/sources');
    final data = _data(res);
    if (data is List) return data.cast<Map<String, dynamic>>();
    return [];
  }

  Future<Map<String, dynamic>> addMarketSource(
      {required String url, String name = ''}) async {
    final res =
        await _dio.post('/market/sources', data: {'url': url, 'name': name});
    return _data(res) as Map<String, dynamic>;
  }

  Future<void> deleteMarketSource(String id) async {
    await _dio.delete('/market/sources/$id');
  }

  Future<Map<String, dynamic>> refreshMarket() async {
    final res = await _dio.post('/market/refresh');
    return _data(res) as Map<String, dynamic>;
  }
}

class ChatStreamEvent {
  final String type;
  final String? content;
  final Map<String, dynamic>? toolCall;
  final Map<String, dynamic>? toolResult;
  final Map<String, dynamic>? approvalRequest;

  ChatStreamEvent(
      {required this.type,
      this.content,
      this.toolCall,
      this.toolResult,
      this.approvalRequest});

  factory ChatStreamEvent.fromJson(Map<String, dynamic> json) {
    return ChatStreamEvent(
      type: json['type'] ?? 'token',
      content: json['content'],
      toolCall: json['tool_call'],
      toolResult: json['tool_result'],
      approvalRequest: json['approval_request'],
    );
  }
}

final apiServiceProvider = Provider<ApiService>((ref) {
  final config = ref.watch(apiConfigProvider);
  return ApiService(config);
});
