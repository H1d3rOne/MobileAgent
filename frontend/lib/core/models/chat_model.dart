import 'package:uuid/uuid.dart';

enum MessageRole { user, assistant, system, tool }

class ToolCall {
  final String id;
  final String name;
  final Map<String, dynamic> arguments;
  final String? result;
  final ToolCallStatus status;
  final bool dangerous;

  const ToolCall({
    required this.id,
    required this.name,
    required this.arguments,
    this.result,
    this.status = ToolCallStatus.pending,
    this.dangerous = false,
  });

  ToolCall copyWith({String? result, ToolCallStatus? status, bool? dangerous}) => ToolCall(
    id: id, name: name, arguments: arguments,
    result: result ?? this.result, status: status ?? this.status,
    dangerous: dangerous ?? this.dangerous,
  );
}

enum ToolCallStatus { pending, waitingApproval, running, completed, error }

class PlanProgress {
  final String goal;
  final List<Map<String, dynamic>> steps; // {index, desc, status}
  final String? replanReason;
  final Map<String, dynamic>? finalEval; // {complete, missing, summary}

  const PlanProgress({this.goal = '', this.steps = const [], this.replanReason, this.finalEval});

  PlanProgress copyWith({String? goal, List<Map<String, dynamic>>? steps, String? replanReason, Map<String, dynamic>? finalEval}) =>
      PlanProgress(
        goal: goal ?? this.goal,
        steps: steps ?? this.steps,
        replanReason: replanReason ?? this.replanReason,
        finalEval: finalEval ?? this.finalEval,
      );
}

class ChatMessage {
  final String id;
  final MessageRole role;
  final String content;
  final DateTime timestamp;
  final List<ToolCall>? toolCalls;
  final List<String>? attachments;
  final PlanProgress? plan;

  const ChatMessage({
    required this.id,
    required this.role,
    required this.content,
    required this.timestamp,
    this.toolCalls,
    this.attachments,
    this.plan,
  });

  ChatMessage copyWith({String? content, List<ToolCall>? toolCalls, PlanProgress? plan}) => ChatMessage(
    id: id, role: role, content: content ?? this.content,
    timestamp: timestamp, toolCalls: toolCalls ?? this.toolCalls,
    attachments: attachments, plan: plan ?? this.plan,
  );
  
  factory ChatMessage.user(String content, {List<String>? attachments}) => ChatMessage(
    id: const Uuid().v4(), role: MessageRole.user, content: content,
    timestamp: DateTime.now(), attachments: attachments,
  );
  
  factory ChatMessage.assistant(String content, {List<ToolCall>? toolCalls}) => ChatMessage(
    id: const Uuid().v4(), role: MessageRole.assistant, content: content,
    timestamp: DateTime.now(), toolCalls: toolCalls,
  );
  
  factory ChatMessage.system(String content) => ChatMessage(
    id: const Uuid().v4(), role: MessageRole.system, content: content,
    timestamp: DateTime.now(),
  );
  
  Map<String, dynamic> toJson() => {
    'id': id, 'role': role.name, 'content': content,
    'timestamp': timestamp.toIso8601String(),
    'tool_calls': toolCalls?.map((t) => {'id': t.id, 'name': t.name, 'arguments': t.arguments, 'result': t.result, 'status': t.status.name, 'dangerous': t.dangerous}).toList(),
    'attachments': attachments,
  };

  factory ChatMessage.fromJson(Map<String, dynamic> json) => ChatMessage(
    id: json['id'], role: MessageRole.values.byName(json['role']),
    content: json['content'], timestamp: DateTime.parse(json['timestamp']),
    toolCalls: (json['tool_calls'] as List?)?.map((t) => ToolCall(
      id: t['id'], name: t['name'], arguments: Map<String, dynamic>.from(t['arguments']),
      result: t['result'], status: ToolCallStatus.values.byName(t['status'] ?? 'pending'),
      dangerous: t['dangerous'] == true,
    )).toList(),
    attachments: (json['attachments'] as List?)?.cast<String>(),
  );
}

class ChatSession {
  final String id;
  final String title;
  final List<ChatMessage> messages;
  final DateTime createdAt;
  final DateTime updatedAt;
  
  const ChatSession({
    required this.id,
    required this.title,
    required this.messages,
    required this.createdAt,
    required this.updatedAt,
  });
  
  ChatSession copyWith({String? id, String? title, List<ChatMessage>? messages, DateTime? updatedAt}) => ChatSession(
    id: id ?? this.id, title: title ?? this.title, messages: messages ?? this.messages,
    createdAt: createdAt, updatedAt: updatedAt ?? this.updatedAt,
  );
  
  factory ChatSession.create({String? title}) => ChatSession(
    id: const Uuid().v4(), title: title ?? 'New Chat',
    messages: [], createdAt: DateTime.now(), updatedAt: DateTime.now(),
  );
}
