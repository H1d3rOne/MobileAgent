import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_markdown/flutter_markdown.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../core/providers/chat_provider.dart';
import '../../core/models/chat_model.dart';
import '../../core/services/api_service.dart';

final _skillsListProvider =
    FutureProvider<List<Map<String, dynamic>>>((ref) async {
  return ref.watch(apiServiceProvider).listSkills();
});

class ChatPage extends ConsumerStatefulWidget {
  const ChatPage({super.key});
  @override
  ConsumerState<ChatPage> createState() => _ChatPageState();
}

class _ChatPageState extends ConsumerState<ChatPage> {
  final _inputController = TextEditingController();
  final _scrollController = ScrollController();
  final _inputFocusNode = FocusNode();
  final LayerLink _inputLink = LayerLink();
  OverlayEntry? _suggestionsOverlay;
  List<Map<String, dynamic>> _filteredSkills = const [];
  int _selectedSuggestion = 0;
  String? _hoveredMessageId;
  int _lastMessageCount = 0;

  @override
  void initState() {
    super.initState();
    _inputController.addListener(_handleInputChanged);
  }

  @override
  void dispose() {
    _hideSuggestions();
    _inputController.removeListener(_handleInputChanged);
    _inputController.dispose();
    _scrollController.dispose();
    _inputFocusNode.dispose();
    super.dispose();
  }

  void _handleInputChanged() {
    final text = _inputController.text;
    if (!text.startsWith('/')) {
      _hideSuggestions();
      return;
    }
    final query = text.substring(1).trim().split(RegExp(r'\s')).first.toLowerCase();
    final all = ref.read(_skillsListProvider).maybeWhen(
          data: (v) => v,
          orElse: () => const <Map<String, dynamic>>[],
        );
    final filtered = query.isEmpty
        ? all
        : all
            .where((s) =>
                (s['name'] ?? '').toString().toLowerCase().contains(query))
            .toList();
    if (filtered.isEmpty) {
      _hideSuggestions();
      return;
    }
    setState(() {
      _filteredSkills = filtered;
      if (_selectedSuggestion >= filtered.length) _selectedSuggestion = 0;
    });
    _showSuggestions();
  }

  void _showSuggestions() {
    if (_suggestionsOverlay != null) {
      _suggestionsOverlay!.markNeedsBuild();
      return;
    }
    _suggestionsOverlay = OverlayEntry(builder: _buildSuggestionsOverlay);
    Overlay.of(context).insert(_suggestionsOverlay!);
  }

  void _hideSuggestions() {
    _suggestionsOverlay?.remove();
    _suggestionsOverlay = null;
    _selectedSuggestion = 0;
  }

  Widget _buildSuggestionsOverlay(BuildContext context) {
    final theme = Theme.of(context);
    return Positioned(
      width: 460,
      child: CompositedTransformFollower(
        link: _inputLink,
        showWhenUnlinked: false,
        targetAnchor: Alignment.topLeft,
        followerAnchor: Alignment.bottomLeft,
        offset: const Offset(0, -4),
        child: Material(
          elevation: 8,
          borderRadius: BorderRadius.circular(8),
          color: theme.cardColor,
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 280),
            child: ListView.builder(
              shrinkWrap: true,
              padding: const EdgeInsets.symmetric(vertical: 4),
              itemCount: _filteredSkills.length,
              itemBuilder: (context, i) {
                final s = _filteredSkills[i];
                final isSelected = i == _selectedSuggestion;
                return InkWell(
                  onTap: () => _applySuggestion(i),
                  child: Container(
                    color: isSelected
                        ? theme.colorScheme.primary.withValues(alpha: 0.12)
                        : null,
                    padding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 8),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '/${s['name'] ?? ''}',
                          style: theme.textTheme.bodyMedium?.copyWith(
                            fontFamily: 'monospace',
                            fontWeight: FontWeight.w600,
                            color: theme.colorScheme.primary,
                          ),
                        ),
                        if ((s['description'] ?? '').toString().isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.only(top: 2),
                            child: Text(
                              s['description'].toString(),
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: theme.textTheme.bodySmall
                                  ?.copyWith(color: Colors.grey),
                            ),
                          ),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
        ),
      ),
    );
  }

  void _applySuggestion(int index) {
    if (index < 0 || index >= _filteredSkills.length) return;
    final name = (_filteredSkills[index]['name'] ?? '').toString();
    final newText = '/$name ';
    _inputController.value = TextEditingValue(
      text: newText,
      selection: TextSelection.collapsed(offset: newText.length),
    );
    _hideSuggestions();
    _inputFocusNode.requestFocus();
  }

  KeyEventResult _onInputKey(FocusNode node, KeyEvent event) {
    if (event is! KeyDownEvent) return KeyEventResult.ignored;

    // Enter without Shift sends the message; Shift+Enter inserts newline.
    if ((event.logicalKey == LogicalKeyboardKey.enter ||
            event.logicalKey == LogicalKeyboardKey.numpadEnter) &&
        !HardwareKeyboard.instance.isShiftPressed) {
      if (_suggestionsOverlay != null && _filteredSkills.isNotEmpty) {
        _applySuggestion(_selectedSuggestion);
      } else {
        final state = ref.read(chatProvider);
        _sendMessage(state);
      }
      return KeyEventResult.handled;
    }

    if (_suggestionsOverlay == null || _filteredSkills.isEmpty) {
      return KeyEventResult.ignored;
    }
    if (event.logicalKey == LogicalKeyboardKey.escape) {
      _hideSuggestions();
      setState(() {});
      return KeyEventResult.handled;
    }
    if (event.logicalKey == LogicalKeyboardKey.arrowDown) {
      setState(() {
        _selectedSuggestion =
            (_selectedSuggestion + 1) % _filteredSkills.length;
      });
      _suggestionsOverlay?.markNeedsBuild();
      return KeyEventResult.handled;
    }
    if (event.logicalKey == LogicalKeyboardKey.arrowUp) {
      setState(() {
        _selectedSuggestion =
            (_selectedSuggestion - 1 + _filteredSkills.length) %
                _filteredSkills.length;
      });
      _suggestionsOverlay?.markNeedsBuild();
      return KeyEventResult.handled;
    }
    if (event.logicalKey == LogicalKeyboardKey.tab) {
      _applySuggestion(_selectedSuggestion);
      return KeyEventResult.handled;
    }
    return KeyEventResult.ignored;
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(chatProvider);
    final theme = Theme.of(context);

    return Row(
      children: [
        // Session sidebar
        SizedBox(
          width: 260,
          child: _buildSessionList(context, state, theme),
        ),
        const VerticalDivider(width: 1),
        // Chat area
        Expanded(
          child: state.currentSession != null
              ? _buildChatArea(context, state, theme)
              : Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.chat_bubble_outline, size: 64, color: Colors.grey[400]),
                      const SizedBox(height: 16),
                      Text('Start a new chat', style: theme.textTheme.headlineMedium),
                      const SizedBox(height: 8),
                      Text('Create a session to begin', style: theme.textTheme.bodySmall),
                      const SizedBox(height: 24),
                      ElevatedButton.icon(
                        onPressed: () => ref.read(chatProvider.notifier).createSession(),
                        icon: const Icon(Icons.add),
                        label: const Text('New Chat'),
                      ),
                    ],
                  ),
                ),
        ),
      ],
    );
  }

  Widget _buildSessionList(BuildContext context, ChatState state, ThemeData theme) {
    final sorted = List<ChatSession>.from(state.sessions)
      ..sort((a, b) => b.updatedAt.compareTo(a.updatedAt));
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              Text('Sessions', style: theme.textTheme.titleLarge),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.add),
                onPressed: () => ref.read(chatProvider.notifier).createSession(),
                tooltip: 'New Chat',
              ),
            ],
          ),
        ),
        Expanded(
          child: sorted.isEmpty
              ? Center(child: Text('No sessions', style: theme.textTheme.bodySmall))
              : ListView.builder(
                  itemCount: sorted.length,
                  itemBuilder: (context, index) {
                    final session = sorted[index];
                    final isSelected = session.id == state.currentSessionId;
                    return ListTile(
                      selected: isSelected,
                      dense: true,
                      leading: const Icon(Icons.chat_bubble_outline, size: 18),
                      title: Text(session.title, maxLines: 1, overflow: TextOverflow.ellipsis, style: theme.textTheme.bodyMedium),
                      subtitle: Text(_relativeTime(session.updatedAt), style: theme.textTheme.bodySmall),
                      onTap: () => ref.read(chatProvider.notifier).selectSession(session.id),
                      trailing: IconButton(
                        icon: const Icon(Icons.delete_outline, size: 16),
                        onPressed: () => ref.read(chatProvider.notifier).deleteSession(session.id),
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }

  String _relativeTime(DateTime dt) {
    final now = DateTime.now();
    final diff = now.difference(dt);
    if (diff.inMinutes < 1) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays == 1) return 'yesterday';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return '${dt.month}/${dt.day}';
  }

  Widget _buildChatArea(BuildContext context, ChatState state, ThemeData theme) {
    final session = state.currentSession!;
    final msgCount = session.messages.length;
    if (msgCount != _lastMessageCount) {
      _lastMessageCount = msgCount;
      _scrollToBottom();
    }

    return Column(
      children: [
        // Header
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: BoxDecoration(
            border: Border(bottom: BorderSide(color: theme.dividerColor)),
          ),
          child: Row(
            children: [
              Text(session.title, style: theme.textTheme.titleMedium),
              const Spacer(),
              if (state.isStreaming)
                TextButton.icon(
                  onPressed: () => ref.read(chatProvider.notifier).stopStreaming(),
                  icon: const Icon(Icons.stop, size: 16),
                  label: const Text('Stop'),
                ),
            ],
          ),
        ),
        // Messages
        Expanded(
          child: ListView.builder(
            controller: _scrollController,
            padding: const EdgeInsets.all(16),
            itemCount: session.messages.length,
            itemBuilder: (context, index) => _buildMessageBubble(session.messages[index], index, theme),
          ),
        ),
        // Input
        _buildInputBar(context, state, theme),
      ],
    );
  }

  Widget _buildMessageBubble(ChatMessage msg, int index, ThemeData theme) {
    final isUser = msg.role == MessageRole.user;
    final maxFactor = isUser ? 0.6 : 0.8;
    final showActions = isUser && _hoveredMessageId == msg.id;
    return MouseRegion(
      onEnter: isUser ? (_) => setState(() => _hoveredMessageId = msg.id) : null,
      onExit: isUser ? (_) => setState(() => _hoveredMessageId = null) : null,
      child: Align(
        alignment: isUser ? Alignment.centerRight : Alignment.centerLeft,
        child: ConstrainedBox(
          constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * maxFactor),
          child: Column(
            crossAxisAlignment: isUser ? CrossAxisAlignment.end : CrossAxisAlignment.start,
            children: [
              Container(
                margin: const EdgeInsets.symmetric(vertical: 4),
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                decoration: BoxDecoration(
                  color: isUser ? theme.colorScheme.primary.withValues(alpha: 0.15) : theme.cardColor,
                  borderRadius: BorderRadius.only(
                    topLeft: const Radius.circular(12),
                    topRight: const Radius.circular(12),
                    bottomLeft: isUser ? const Radius.circular(12) : Radius.zero,
                    bottomRight: isUser ? Radius.zero : const Radius.circular(12),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    if (msg.toolCalls != null && msg.toolCalls!.isNotEmpty)
                      ...msg.toolCalls!.map((tc) => _buildToolCallChip(tc, theme)),
                    if (msg.content.isNotEmpty)
                      isUser
                          ? SelectableText(msg.content, style: theme.textTheme.bodyMedium)
                          : MarkdownBody(
                              data: msg.content,
                              selectable: true,
                              styleSheet: MarkdownStyleSheet.fromTheme(theme).copyWith(
                                p: theme.textTheme.bodyMedium,
                                code: theme.textTheme.bodySmall?.copyWith(
                                  fontFamily: 'monospace',
                                  backgroundColor: theme.colorScheme.surfaceContainerHighest,
                                ),
                                codeblockDecoration: BoxDecoration(
                                  color: theme.colorScheme.surfaceContainerHighest,
                                  borderRadius: BorderRadius.circular(8),
                                ),
                              ),
                            ),
                  ],
                ),
              ),
              if (isUser)
                AnimatedOpacity(
                  opacity: showActions ? 1.0 : 0.0,
                  duration: const Duration(milliseconds: 150),
                  child: Padding(
                    padding: const EdgeInsets.only(right: 4),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _msgActionIcon(Icons.copy, () {
                          Clipboard.setData(ClipboardData(text: msg.content));
                          ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Copied'), duration: Duration(seconds: 1)));
                        }, theme),
                        _msgActionIcon(Icons.delete_outline, () {
                          ref.read(chatProvider.notifier).deleteMessage(msg.id);
                        }, theme),
                        _msgActionIcon(Icons.undo, () {
                          ref.read(chatProvider.notifier).rollbackToMessage(msg.id).then((content) {
                            if (content != null && content.isNotEmpty && mounted) {
                              _inputController.text = content;
                              _inputFocusNode.requestFocus();
                            }
                          });
                        }, theme),
                      ],
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _msgActionIcon(IconData icon, VoidCallback onTap, ThemeData theme) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(4),
      child: Padding(
        padding: const EdgeInsets.all(4),
        child: Icon(icon, size: 16, color: theme.colorScheme.onSurface.withValues(alpha: 0.6)),
      ),
    );
  }

  Widget _buildToolCallChip(ToolCall tc, ThemeData theme) {
    final isCompleted = tc.status == ToolCallStatus.completed;
    final isError = tc.status == ToolCallStatus.error;
    final isWaiting = tc.status == ToolCallStatus.waitingApproval;
    final color = isError
        ? Colors.red
        : (isCompleted
            ? Colors.green
            : (isWaiting ? Colors.orange : theme.colorScheme.tertiary));
    return Container(
      margin: const EdgeInsets.only(top: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: ExpansionTile(
        initiallyExpanded: isWaiting,
        tilePadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 0),
        childrenPadding: const EdgeInsets.fromLTRB(12, 0, 12, 8),
        dense: true,
        leading: Icon(
          isError
              ? Icons.error_outline
              : (isCompleted
                  ? Icons.check_circle
                  : (isWaiting ? Icons.warning_amber_rounded : Icons.sync)),
          size: 16,
          color: color,
        ),
        title: Row(
          children: [
            Expanded(
              child: Text(
                tc.name,
                style: theme.textTheme.bodySmall?.copyWith(
                  fontWeight: FontWeight.w600,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            if (isWaiting)
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: Colors.orange.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  'Approval needed',
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: Colors.orange[800],
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
          ],
        ),
        subtitle: tc.arguments.isEmpty
            ? null
            : Text(
                tc.arguments.entries
                    .map((e) => '${e.key}=${e.value}')
                    .join(', '),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontFamily: 'monospace',
                ),
              ),
        children: [
          if (tc.arguments.isNotEmpty) ...[
            Align(
              alignment: Alignment.centerLeft,
              child: Text('Arguments', style: theme.textTheme.labelSmall),
            ),
            const SizedBox(height: 4),
            SelectableText(
              const JsonEncoder.withIndent('  ').convert(tc.arguments),
              style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
            ),
          ],
          if (isWaiting) ...[
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.orange.withValues(alpha: 0.05),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: Colors.orange.withValues(alpha: 0.2)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'This tool is marked dangerous. Approve to execute, or deny to skip.',
                    style: theme.textTheme.bodySmall,
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      ElevatedButton.icon(
                        onPressed: () => ref
                            .read(chatProvider.notifier)
                            .respondToApproval(tc.id, true),
                        icon: const Icon(Icons.check, size: 16),
                        label: const Text('Approve'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.green,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                        ),
                      ),
                      const SizedBox(width: 8),
                      OutlinedButton.icon(
                        onPressed: () => ref
                            .read(chatProvider.notifier)
                            .respondToApproval(tc.id, false),
                        icon: const Icon(Icons.close, size: 16),
                        label: const Text('Deny'),
                        style: OutlinedButton.styleFrom(
                          foregroundColor: Colors.red,
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
          if (tc.result != null && tc.result!.isNotEmpty) ...[
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerLeft,
              child: Text('Result', style: theme.textTheme.labelSmall),
            ),
            const SizedBox(height: 4),
            SelectableText(
              tc.result!,
              style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildInputBar(BuildContext context, ChatState state, ThemeData theme) {
    // Ensure skill list is fetched.
    ref.watch(_skillsListProvider);
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        border: Border(top: BorderSide(color: theme.dividerColor)),
      ),
      child: Row(
        children: [
          Expanded(
            child: CompositedTransformTarget(
              link: _inputLink,
              child: Focus(
                onKeyEvent: _onInputKey,
                child: TextField(
                  controller: _inputController,
                  focusNode: _inputFocusNode,
                  enabled: !state.isStreaming,
                  decoration: const InputDecoration(
                    hintText: 'Type a message, or "/" to call a skill…',
                    isDense: true,
                  ),
                  maxLines: 3,
                  minLines: 1,
                  onSubmitted: (_) {
                    if (_suggestionsOverlay != null &&
                        _filteredSkills.isNotEmpty) {
                      _applySuggestion(_selectedSuggestion);
                    } else {
                      _sendMessage(state);
                    }
                  },
                ),
              ),
            ),
          ),
          const SizedBox(width: 8),
          IconButton(
            icon: state.isStreaming
                ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.send),
            onPressed: state.isStreaming ? null : () => _sendMessage(state),
          ),
        ],
      ),
    );
  }

  void _sendMessage(ChatState state) {
    final text = _inputController.text.trim();
    if (text.isEmpty || state.currentSessionId == null) return;
    _hideSuggestions();
    _inputController.clear();
    final config = ref.read(apiConfigProvider);
    ref.read(chatProvider.notifier).sendMessage(text, config: config);
  }
}

