import 'dart:async';
import 'dart:convert';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/chat_model.dart';
import '../services/api_service.dart';

class ChatNotifier extends StateNotifier<ChatState> {
  final Ref _ref;
  ChatNotifier(this._ref) : super(ChatState()) {
    loadSessions();
  }

  ApiService get _api => ApiService(_ref.read(apiConfigProvider));

  Future<void> loadSessions() async {
    state = state.copyWith(loading: true);
    try {
      final conversations = await _api.listConversations();
      final parsed = conversations.map((s) => ChatSession(
        id: s['id'] ?? '',
        title: s['title'] ?? s['description'] ?? 'New Chat',
        messages: [],
        createdAt: DateTime.tryParse(s['created_at'] ?? '') ?? DateTime.now(),
        updatedAt: DateTime.tryParse(s['updated_at'] ?? '') ?? DateTime.now(),
      )).toList()
        ..sort((a, b) => b.updatedAt.compareTo(a.updatedAt));
      // Preserve messages for sessions already loaded in memory.
      final existing = {for (final s in state.sessions) s.id: s};
      final merged = parsed.map((s) {
        final old = existing[s.id];
        if (old != null && old.messages.isNotEmpty) {
          return s.copyWith(messages: old.messages);
        }
        return s;
      }).toList();
      state = state.copyWith(sessions: merged, loading: false);
    } catch (e) {
      state = state.copyWith(loading: false, error: e.toString());
    }
  }

  Future<void> createSession({String? title}) async {
    final sessionId = 'session_${DateTime.now().millisecondsSinceEpoch}';
    final session = ChatSession(
      id: sessionId, title: title ?? 'New Chat',
      messages: [], createdAt: DateTime.now(), updatedAt: DateTime.now(),
    );
    state = state.copyWith(
      sessions: [session, ...state.sessions],
      currentSessionId: session.id,
    );
  }

  Future<void> selectSession(String sessionId) async {
    state = state.copyWith(currentSessionId: sessionId);
    final session = state.sessions.firstWhere((s) => s.id == sessionId);
    if (session.messages.isEmpty) {
      try {
        final conv = await _api.getConversation(sessionId);
        final actions = (conv['actions'] as List?) ?? [];
        final messages = _rebuildMessagesFromActions(actions);
        state = state.copyWith(
          sessions: state.sessions.map((s) => s.id == sessionId ? s.copyWith(messages: messages) : s).toList(),
        );
      } catch (_) {}
    }
    await _restorePendingApprovals(sessionId);
  }

  List<ChatMessage> _rebuildMessagesFromActions(List actions) {
    final messages = <ChatMessage>[];
    ChatMessage? lastAssistant;

    for (final a in actions) {
      final type = a['type']?.toString() ?? '';
      final content = a['content']?.toString() ?? '';
      final actionId = a['id']?.toString() ?? '';

      switch (type) {
        case 'user_message':
          if (lastAssistant != null) {
            messages.add(lastAssistant);
            lastAssistant = null;
          }
          messages.add(ChatMessage(
            id: actionId, role: MessageRole.user, content: content,
            timestamp: DateTime.tryParse(a['created_at']?.toString() ?? '') ?? DateTime.now(),
          ));
          break;
        case 'assistant_message':
          if (lastAssistant != null) {
            lastAssistant = lastAssistant.copyWith(
              content: lastAssistant.content + content,
            );
          } else {
            lastAssistant = ChatMessage(
              id: actionId, role: MessageRole.assistant, content: content,
              timestamp: DateTime.tryParse(a['created_at']?.toString() ?? '') ?? DateTime.now(),
            );
          }
          break;
        case 'tool_call':
          lastAssistant ??= ChatMessage.assistant('');
          final calls = List<ToolCall>.from(lastAssistant.toolCalls ?? []);
          calls.add(ToolCall(
            id: a['tool_call_id']?.toString() ?? '',
            name: a['tool_name']?.toString() ?? '',
            arguments: _parseArgs(a['tool_args']),
            status: ToolCallStatus.completed,
          ));
          lastAssistant = lastAssistant.copyWith(toolCalls: calls);
          break;
        case 'tool_result':
          if (lastAssistant != null) {
            final calls = List<ToolCall>.from(lastAssistant.toolCalls ?? []);
            final callId = a['tool_call_id']?.toString() ?? '';
            final idx = calls.indexWhere((c) => c.id == callId);
            if (idx != -1) {
              calls[idx] = calls[idx].copyWith(
                result: a['result']?.toString() ?? content,
                status: ToolCallStatus.completed,
              );
              lastAssistant = lastAssistant.copyWith(toolCalls: calls);
            }
          }
          break;
      }
    }
    if (lastAssistant != null) messages.add(lastAssistant);
    return messages;
  }

  Map<String, dynamic> _parseArgs(dynamic raw) {
    if (raw is Map) return Map<String, dynamic>.from(raw);
    if (raw is String && raw.isNotEmpty) {
      try {
        final decoded = Uri.decodeFull(raw);
        if (decoded.startsWith('{')) {
          return Map<String, dynamic>.from(
            (const JsonDecoder().convert(decoded)) as Map,
          );
        }
      } catch (_) {}
    }
    return {};
  }

  Future<void> _restorePendingApprovals(String sessionId) async {
    try {
      final pending = await _api.listPendingApprovals(sessionId);
      if (pending.isEmpty) return;
      final sessions = state.sessions;
      final idx = sessions.indexWhere((s) => s.id == sessionId);
      if (idx == -1) return;
      final session = sessions[idx];
      final msgs = List<ChatMessage>.from(session.messages);

      // Append a synthetic assistant message with the pending approval tool calls.
      final toolCalls = pending.map((p) => ToolCall(
        id: p['id'] ?? '',
        name: p['name'] ?? '',
        arguments: Map<String, dynamic>.from(p['arguments'] ?? {}),
        status: ToolCallStatus.waitingApproval,
        dangerous: true,
      )).toList();

      // Check if the last assistant message already has these tool calls (avoid duplicates).
      final lastAssistant = msgs.lastIndexWhere((m) => m.role == MessageRole.assistant);
      if (lastAssistant != -1) {
        final existing = msgs[lastAssistant].toolCalls ?? [];
        final existingIds = existing.map((t) => t.id).toSet();
        final newCalls = toolCalls.where((t) => !existingIds.contains(t.id)).toList();
        if (newCalls.isNotEmpty) {
          msgs[lastAssistant] = msgs[lastAssistant].copyWith(
            toolCalls: [...existing, ...newCalls],
          );
        }
      } else if (toolCalls.isNotEmpty) {
        msgs.add(ChatMessage.assistant('', toolCalls: toolCalls));
      }

      state = state.copyWith(
        sessions: sessions.map((s) => s.id == sessionId ? s.copyWith(messages: msgs) : s).toList(),
      );
    } catch (_) {}
  }
  
  Future<void> deleteSession(String sessionId) async {
    try {
      await _api.deleteConversation(sessionId);
      state = state.copyWith(
        sessions: state.sessions.where((s) => s.id != sessionId).toList(),
        currentSessionId: state.currentSessionId == sessionId ? null : state.currentSessionId,
      );
    } catch (e) {
      state = state.copyWith(error: e.toString());
    }
  }
  
  Future<void> sendMessage(String content, {List<String>? attachments, ApiConfig? config}) async {
    final sessionId = state.currentSessionId;
    if (sessionId == null) return;

    final userMsg = ChatMessage.user(content, attachments: attachments);
    final assistantMsg = ChatMessage.assistant('');

    // Auto-generate title from first message.
    final session = state.sessions.firstWhere((s) => s.id == sessionId);
    String? newTitle;
    if (session.messages.isEmpty) {
      final runes = content.runes.toList();
      newTitle = runes.length > 30
          ? '${String.fromCharCodes(runes.sublist(0, 30))}…'
          : content;
    }

    state = state.copyWith(
      sessions: state.sessions.map((s) => s.id == sessionId
        ? s.copyWith(
            messages: [...s.messages, userMsg, assistantMsg],
            updatedAt: DateTime.now(),
            title: newTitle ?? s.title,
          )
        : s
      ).toList(),
      isStreaming: true,
    );

    try {
      final ApiConfig effectiveConfig = config ?? _ref.read(apiConfigProvider);
      final api = ApiService(effectiveConfig);
      await for (final event in api.streamChat(sessionId, content, attachmentPaths: attachments)) {
        final sessions = state.sessions;
        final idx = sessions.indexWhere((s) => s.id == sessionId);
        if (idx == -1) continue;
        final session = sessions[idx];
        final msgs = List<ChatMessage>.from(session.messages);
        final lastIdx = msgs.lastIndexWhere((m) => m.id == assistantMsg.id);
        if (lastIdx == -1) continue;
        
        switch (event.type) {
          case 'meta':
            // Update session ID from server-assigned conversation_id
            if (event.content != null && event.content!.isNotEmpty) {
              final serverId = event.content!;
              if (sessionId != serverId) {
                state = state.copyWith(
                  currentSessionId: serverId,
                  sessions: state.sessions.map((s) => s.id == sessionId ? s.copyWith(id: serverId) : s).cast<ChatSession>().toList(),
                );
              }
            }
            break;
          case 'token':
            msgs[lastIdx] = msgs[lastIdx].copyWith(content: msgs[lastIdx].content + (event.content ?? ''));
            break;
          case 'tool_call':
            final calls = List<ToolCall>.from(msgs[lastIdx].toolCalls ?? []);
            // If a placeholder waitingApproval entry exists for this id, transition it to running.
            final id = event.toolCall?['id'] ?? '';
            final pendingIdx = calls.indexWhere((c) => c.id == id && c.status == ToolCallStatus.waitingApproval);
            if (pendingIdx != -1) {
              calls[pendingIdx] = calls[pendingIdx].copyWith(status: ToolCallStatus.running);
            } else {
              calls.add(ToolCall(
                id: id, name: event.toolCall?['name'] ?? '',
                arguments: Map<String, dynamic>.from(event.toolCall?['arguments'] ?? {}),
                status: ToolCallStatus.running,
              ));
            }
            msgs[lastIdx] = msgs[lastIdx].copyWith(toolCalls: calls);
            break;
          case 'tool_result':
            final calls = List<ToolCall>.from(msgs[lastIdx].toolCalls ?? []);
            final callIdx = calls.indexWhere((c) => c.id == (event.toolResult?['id'] ?? ''));
            if (callIdx != -1) {
              calls[callIdx] = calls[callIdx].copyWith(
                result: event.toolResult?['content'] ?? '',
                status: (event.toolResult?['error'] == true)
                    ? ToolCallStatus.error
                    : ToolCallStatus.completed,
              );
              msgs[lastIdx] = msgs[lastIdx].copyWith(toolCalls: calls);
            }
            break;
          case 'approval_request':
            final calls = List<ToolCall>.from(msgs[lastIdx].toolCalls ?? []);
            calls.add(ToolCall(
              id: event.approvalRequest?['id'] ?? '',
              name: event.approvalRequest?['name'] ?? '',
              arguments: Map<String, dynamic>.from(event.approvalRequest?['arguments'] ?? {}),
              status: ToolCallStatus.waitingApproval,
              dangerous: true,
            ));
            msgs[lastIdx] = msgs[lastIdx].copyWith(toolCalls: calls);
            break;
          case 'done':
            state = state.copyWith(isStreaming: false);
            return;
          case 'error':
            msgs[lastIdx] = msgs[lastIdx].copyWith(content: 'Error: ${event.content}');
            state = state.copyWith(isStreaming: false, sessions: sessions.map((s) => s.id == sessionId ? s.copyWith(messages: msgs) : s).toList());
            return;
        }
        state = state.copyWith(
          sessions: sessions.map((s) => s.id == sessionId ? s.copyWith(messages: msgs) : s).toList(),
        );
      }
    } catch (e) {
      final sessions = state.sessions;
      final idx = sessions.indexWhere((s) => s.id == sessionId);
      if (idx != -1) {
        final msgs = List<ChatMessage>.from(sessions[idx].messages);
        final lastIdx = msgs.lastIndexWhere((m) => m.id == assistantMsg.id);
        if (lastIdx != -1) msgs[lastIdx] = msgs[lastIdx].copyWith(content: 'Error: $e');
        state = state.copyWith(
          sessions: sessions.map((s) => s.id == sessionId ? s.copyWith(messages: msgs) : s).toList(),
          isStreaming: false,
        );
      }
    }
  }
  
  void stopStreaming() {
    state = state.copyWith(isStreaming: false);
  }

  void deleteMessage(String messageId) {
    final sessionId = state.currentSessionId;
    if (sessionId == null) return;
    state = state.copyWith(
      sessions: state.sessions.map((s) {
        if (s.id != sessionId) return s;
        return s.copyWith(messages: s.messages.where((m) => m.id != messageId).toList());
      }).toList(),
    );
  }

  Future<String?> rollbackToMessage(String messageId) async {
    final sessionId = state.currentSessionId;
    if (sessionId == null) return null;
    // Find the message to get its content before truncating.
    String? rolledBackContent;
    final session = state.sessions.firstWhere((s) => s.id == sessionId);
    final msgIdx = session.messages.indexWhere((m) => m.id == messageId);
    if (msgIdx != -1 && session.messages[msgIdx].role == MessageRole.user) {
      rolledBackContent = session.messages[msgIdx].content;
    }
    // Truncate local messages.
    state = state.copyWith(
      sessions: state.sessions.map((s) {
        if (s.id != sessionId) return s;
        final idx = s.messages.indexWhere((m) => m.id == messageId);
        if (idx <= 0) return s.copyWith(messages: []);
        return s.copyWith(messages: s.messages.sublist(0, idx));
      }).toList(),
    );
    // Persist rollback to backend (best-effort).
    try {
      await _api.rollbackConversation(sessionId, messageId);
    } catch (_) {}
    return rolledBackContent;
  }

  Future<void> respondToApproval(String toolCallId, bool approved) async {
    try {
      final response = await _api.approveToolCall(toolCallId, approved);
      final sessionId = state.currentSessionId;
      if (sessionId == null) return;
      final sessions = state.sessions;
      final idx = sessions.indexWhere((s) => s.id == sessionId);
      if (idx == -1) return;
      final session = sessions[idx];
      final msgs = List<ChatMessage>.from(session.messages);

      // The backend returns {executed: true, result: "..."} when the Run was
      // already dead and it executed the tool directly on approval.
      final executed = response['executed'] == true;
      final result = response['result']?.toString();

      for (var i = 0; i < msgs.length; i++) {
        final calls = msgs[i].toolCalls;
        if (calls == null) continue;
        final cIdx = calls.indexWhere((c) => c.id == toolCallId);
        if (cIdx == -1) continue;
        final updated = List<ToolCall>.from(calls);
        if (!approved) {
          updated[cIdx] = updated[cIdx].copyWith(
            status: ToolCallStatus.error,
            result: 'Denied by user',
          );
        } else if (executed && result != null) {
          // Tool was executed immediately by the backend (late approval).
          updated[cIdx] = updated[cIdx].copyWith(
            status: (response['error'] != null)
                ? ToolCallStatus.error
                : ToolCallStatus.completed,
            result: result,
          );
        } else {
          // Run is still alive — it will send tool_result via SSE.
          updated[cIdx] = updated[cIdx].copyWith(status: ToolCallStatus.running);
        }
        msgs[i] = msgs[i].copyWith(toolCalls: updated);
        break;
      }
      state = state.copyWith(
        sessions: sessions.map((s) => s.id == sessionId ? s.copyWith(messages: msgs) : s).toList(),
      );
    } catch (e) {
      state = state.copyWith(error: e.toString());
    }
  }
}

class ChatState {
  final List<ChatSession> sessions;
  final String? currentSessionId;
  final bool isStreaming;
  final bool loading;
  final String? error;
  
  const ChatState({
    this.sessions = const [],
    this.currentSessionId,
    this.isStreaming = false,
    this.loading = false,
    this.error,
  });
  
  ChatState copyWith({List<ChatSession>? sessions, String? currentSessionId, bool? isStreaming, bool? loading, String? error}) =>
      ChatState(
        sessions: sessions ?? this.sessions,
        currentSessionId: currentSessionId ?? this.currentSessionId,
        isStreaming: isStreaming ?? this.isStreaming,
        loading: loading ?? this.loading,
        error: error,
      );
  
  ChatSession? get currentSession => sessions.where((s) => s.id == currentSessionId).firstOrNull;
}

final chatProvider = StateNotifierProvider<ChatNotifier, ChatState>((ref) {
  return ChatNotifier(ref);
});
