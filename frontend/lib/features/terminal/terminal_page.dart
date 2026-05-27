import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../core/services/termux_service.dart';

class TerminalPage extends ConsumerStatefulWidget {
  const TerminalPage({super.key});
  @override
  ConsumerState<TerminalPage> createState() => _TerminalPageState();
}

class _TerminalPageState extends ConsumerState<TerminalPage> {
  final _input = TextEditingController();
  final _scroll = ScrollController();
  final List<_Entry> _history = [];
  bool _busy = false;

  @override
  void dispose() {
    _input.dispose();
    _scroll.dispose();
    super.dispose();
  }

  Future<void> _run() async {
    final cmd = _input.text.trim();
    if (cmd.isEmpty || _busy) return;
    _input.clear();
    setState(() {
      _busy = true;
      _history.add(_Entry.command(cmd));
    });
    try {
      final res = await ref.read(termuxServiceProvider).exec(cmd);
      setState(() {
        if (res.stdout.isNotEmpty) _history.add(_Entry.stdout(res.stdout));
        if (res.stderr.isNotEmpty) _history.add(_Entry.stderr(res.stderr));
        _history.add(_Entry.exit(res.exit));
      });
    } catch (e) {
      setState(() => _history.add(_Entry.stderr(e.toString())));
    } finally {
      setState(() => _busy = false);
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (_scroll.hasClients) {
          _scroll.animateTo(
            _scroll.position.maxScrollExtent,
            duration: const Duration(milliseconds: 150),
            curve: Curves.easeOut,
          );
        }
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final available = ref.watch(termuxAvailableProvider);

    return available.when(
      data: (ok) {
        if (!ok) return _unavailable(theme);
        return Column(
          children: [
            Expanded(
              child: Container(
                color: Colors.black,
                child: ListView.builder(
                  controller: _scroll,
                  padding: const EdgeInsets.all(12),
                  itemCount: _history.length,
                  itemBuilder: (_, i) {
                    final e = _history[i];
                    return SelectableText(
                      e.label,
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 13,
                        color: e.color,
                      ),
                    );
                  },
                ),
              ),
            ),
            Container(
              padding: const EdgeInsets.all(8),
              color: theme.cardColor,
              child: Row(
                children: [
                  const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 8),
                    child: Text('\$', style: TextStyle(fontFamily: 'monospace')),
                  ),
                  Expanded(
                    child: TextField(
                      controller: _input,
                      enabled: !_busy,
                      style: const TextStyle(fontFamily: 'monospace'),
                      decoration: const InputDecoration(
                        hintText: 'enter shell command',
                        isDense: true,
                        border: InputBorder.none,
                      ),
                      onSubmitted: (_) => _run(),
                    ),
                  ),
                  IconButton(
                    icon: _busy
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.play_arrow),
                    onPressed: _busy ? null : _run,
                  ),
                ],
              ),
            ),
          ],
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (e, _) => Center(child: Text('Error: $e')),
    );
  }

  Widget _unavailable(ThemeData theme) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.terminal, size: 48, color: theme.colorScheme.onSurfaceVariant),
            const SizedBox(height: 16),
            Text('Termux not available', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(
              'This terminal requires Termux installed on Android with '
              '`allow-external-apps=true` set in ~/.termux/termux.properties '
              'and the `com.termux.permission.RUN_COMMAND` permission granted.',
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}

class _Entry {
  final String label;
  final Color color;
  _Entry._(this.label, this.color);
  factory _Entry.command(String c) => _Entry._('\$ $c', Colors.greenAccent);
  factory _Entry.stdout(String s) => _Entry._(s.trimRight(), Colors.white);
  factory _Entry.stderr(String s) => _Entry._(s.trimRight(), Colors.redAccent);
  factory _Entry.exit(int code) => _Entry._('[exit $code]', Colors.grey);
}
