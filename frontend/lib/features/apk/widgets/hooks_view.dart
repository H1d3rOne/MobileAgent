import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/models/apk_model.dart';
import '../../../core/providers/apk_provider.dart';
import '../../../core/services/api_service.dart';

class HooksView extends ConsumerStatefulWidget {
  const HooksView({super.key});

  @override
  ConsumerState<HooksView> createState() => _HooksViewState();
}

class _HooksViewState extends ConsumerState<HooksView> {
  bool _running = false;
  List<Map<String, dynamic>>? _data;

  @override
  void initState() {
    super.initState();
    final apk = ref.read(apkProvider).selected;
    if (apk != null && _data == null) _generate(apk);
  }

  Future<void> _generate(ApkInfo apk) async {
    if (apk.id == null) {
      setState(() => _data = [{'error': 'APK has no ID'}]);
      return;
    }
    setState(() { _running = true; _data = null; });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.generateHooks(apk.id!);
      final hooks = (res['hooks'] as List?)?.cast<Map<String, dynamic>>() ?? [];
      setState(() { _data = hooks; _running = false; });
    } catch (e) {
      setState(() { _data = [{'error': e.toString()}]; _running = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    if (_running) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 12),
            Text('Generating Frida hooks from analysis...'),
          ],
        ),
      );
    }

    if (_data == null || _data!.isEmpty) {
      return Center(
        child: Text('Click Hooks to auto-generate Frida scripts based on analysis results.',
            style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
      );
    }

    if (_data!.length == 1 && _data!.first.containsKey('error')) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline, size: 36, color: theme.colorScheme.error),
              const SizedBox(height: 8),
              SelectableText(_data!.first['error'].toString(),
                  style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
            ],
          ),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Text('Generated Hooks (${_data!.length})', style: theme.textTheme.titleMedium),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.copy_all, size: 16),
                tooltip: 'Copy all hooks',
                onPressed: () {
                  final all = _data!.map((h) => '// ${h['name']}\n${h['code'] ?? ''}').join('\n\n');
                  Clipboard.setData(ClipboardData(text: all));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('All hooks copied'), duration: Duration(seconds: 1)),
                  );
                },
              ),
              IconButton(
                icon: const Icon(Icons.refresh, size: 16),
                tooltip: 'Regenerate',
                onPressed: () {
                  final apk = ref.read(apkProvider).selected;
                  if (apk != null) _generate(apk);
                },
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.all(12),
            itemCount: _data!.length,
            itemBuilder: (ctx, i) {
              final hook = _data![i];
              final name = hook['name']?.toString() ?? 'Hook ${i + 1}';
              final category = hook['category']?.toString() ?? '';
              final description = hook['description']?.toString() ?? '';
              final code = hook['code']?.toString() ?? '';
              final reason = hook['reason']?.toString() ?? '';

              return Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Container(
                  decoration: BoxDecoration(
                    border: Border(left: BorderSide(color: theme.colorScheme.primary, width: 3)),
                    color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Theme(
                    data: theme.copyWith(dividerColor: Colors.transparent),
                    child: ExpansionTile(
                      tilePadding: const EdgeInsets.symmetric(horizontal: 12),
                      childrenPadding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
                      title: Row(
                        children: [
                          Expanded(
                            child: Text(name, style: theme.textTheme.bodyMedium?.copyWith(fontWeight: FontWeight.w600)),
                          ),
                          if (category.isNotEmpty)
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                              decoration: BoxDecoration(
                                color: theme.colorScheme.primary.withValues(alpha: 0.1),
                                borderRadius: BorderRadius.circular(3),
                              ),
                              child: Text(category, style: const TextStyle(fontSize: 10)),
                            ),
                        ],
                      ),
                      subtitle: description.isNotEmpty
                          ? Text(description, style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey))
                          : null,
                      children: [
                        if (reason.isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.only(bottom: 8),
                            child: Text('Reason: $reason',
                                style: theme.textTheme.bodySmall?.copyWith(fontStyle: FontStyle.italic, color: Colors.grey)),
                          ),
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: theme.colorScheme.surface,
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: theme.dividerColor),
                          ),
                          child: Stack(
                            children: [
                              SelectableText(code,
                                  style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', fontSize: 11)),
                              Positioned(
                                top: 0,
                                right: 0,
                                child: IconButton(
                                  icon: const Icon(Icons.copy, size: 14),
                                  tooltip: 'Copy',
                                  onPressed: () {
                                    Clipboard.setData(ClipboardData(text: code));
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      const SnackBar(content: Text('Hook copied'), duration: Duration(seconds: 1)),
                                    );
                                  },
                                  visualDensity: VisualDensity.compact,
                                  padding: EdgeInsets.zero,
                                  constraints: const BoxConstraints(minWidth: 24, minHeight: 24),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              );
            },
          ),
        ),
      ],
    );
  }
}
