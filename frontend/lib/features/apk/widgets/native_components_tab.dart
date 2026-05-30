import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/providers/apk_provider.dart';
import '../../../core/services/api_service.dart';
import 'result_panel.dart';

String _shellQuote(String s) => "'${s.replaceAll("'", "'\\''")}'";

final _toolsStatusProvider = FutureProvider<Map<String, bool>>((ref) async {
  final list = await ref.watch(apiServiceProvider).toolsStatus();
  return {
    for (final t in list) (t['name'] ?? '').toString(): t['available'] == true,
  };
});

class _ToolMissingBanner extends ConsumerWidget {
  final String tool;
  const _ToolMissingBanner({required this.tool});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final status = ref.watch(_toolsStatusProvider);
    final missing = status.maybeWhen(
      data: (m) => m.containsKey(tool) && m[tool] == false,
      orElse: () => false,
    );
    if (!missing) return const SizedBox.shrink();
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      color: Colors.orange.withValues(alpha: 0.12),
      child: Row(children: [
        const Icon(Icons.warning_amber, size: 16, color: Colors.orange),
        const SizedBox(width: 8),
        Expanded(
          child: Text('$tool is not installed — these actions will fail. Configure tools.$tool in config.yaml or install it.',
              style: theme.textTheme.bodySmall?.copyWith(color: Colors.orange[900])),
        ),
      ]),
    );
  }
}

class NativeTab extends ConsumerStatefulWidget {
  const NativeTab({super.key});

  @override
  ConsumerState<NativeTab> createState() => _NativeTabState();
}

class _NativeTabState extends ConsumerState<NativeTab> {
  final _fileController = TextEditingController();
  bool _running = false;
  String? _result;

  @override
  void dispose() {
    _fileController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final apk = ref.watch(apkProvider).selected!;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const _ToolMissingBanner(tool: 'radare2'),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: TextField(
                controller: _fileController,
                decoration: InputDecoration(
                  labelText: 'File path (.so or DEX)',
                  hintText: 'lib/arm64-v8a/libnative.so',
                  border: const OutlineInputBorder(), isDense: true,
                  contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  suffixIcon: IconButton(
                    icon: const Icon(Icons.folder_open, size: 16),
                    tooltip: 'Use APK lib path',
                    onPressed: () {
                      final base = apk.decompiledPath ?? apk.path;
                      _fileController.text = '$base/lib/';
                    },
                  ),
                ),
              )),
            ]),
            const SizedBox(height: 8),
            Wrap(spacing: 6, runSpacing: 6, children: [
              _chip('Info', Icons.info_outline, 'info'),
              _chip('Symbols', Icons.list, 'symbols'),
              _chip('Imports', Icons.input, 'imports'),
              _chip('Strings', Icons.text_fields, 'strings'),
              _chip('Functions', Icons.functions, 'functions'),
            ]),
          ]),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: ResultPanel(
              content: _result,
              isRunning: _running,
              isError: _result?.startsWith('Error') ?? false,
              emptyHint: 'Analyze native .so binaries (via radare2)',
            ),
          ),
        ),
      ],
    );
  }

  Widget _chip(String label, IconData icon, String action) {
    return ActionChip(
      avatar: Icon(icon, size: 14),
      label: Text(label, style: const TextStyle(fontSize: 12)),
      onPressed: _running ? null : () => _run(action),
      visualDensity: VisualDensity.compact,
      materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
    );
  }

  Future<void> _run(String action) async {
    final filePath = _fileController.text.trim();
    if (filePath.isEmpty) {
      setState(() => _result = 'Error: file path is required');
      return;
    }
    setState(() { _running = true; _result = null; });
    try {
      final api = ref.read(apiServiceProvider);
      const cmdMap = {
        'info': 'iI', 'symbols': 'is', 'imports': 'ii',
        'strings': 'iz', 'functions': 'afl',
      };
      final res = await api.shellCommand('r2 -q -c ${_shellQuote(cmdMap[action]!)} ${_shellQuote(filePath)}');
      setState(() { _result = res['output']?.toString() ?? 'No output'; _running = false; });
    } catch (e) {
      setState(() { _result = 'Error: $e'; _running = false; });
    }
  }
}

class ComponentsTab extends ConsumerStatefulWidget {
  const ComponentsTab({super.key});

  @override
  ConsumerState<ComponentsTab> createState() => _ComponentsTabState();
}

class _ComponentsTabState extends ConsumerState<ComponentsTab> {
  bool _running = false;
  String? _result;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const _ToolMissingBanner(tool: 'androguard'),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Wrap(spacing: 6, runSpacing: 6, children: [
            _chip('Permissions', Icons.security, 'permissions'),
            _chip('Activities', Icons.view_list, 'activities'),
            _chip('Services', Icons.miscellaneous_services, 'services'),
            _chip('Receivers', Icons.broadcast_on_personal, 'receivers'),
            _chip('Providers', Icons.storage, 'providers'),
            _chip('Manifest', Icons.description, 'manifest'),
          ]),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: ResultPanel(
              content: _result,
              isRunning: _running,
              isError: _result?.startsWith('Error') ?? false,
              emptyHint: 'Inspect APK components: permissions, activities, services (via androguard)',
            ),
          ),
        ),
      ],
    );
  }

  Widget _chip(String label, IconData icon, String action) {
    return ActionChip(
      avatar: Icon(icon, size: 14),
      label: Text(label, style: const TextStyle(fontSize: 12)),
      onPressed: _running ? null : () => _run(action),
      visualDensity: VisualDensity.compact,
      materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
    );
  }

  Future<void> _run(String action) async {
    final apk = ref.read(apkProvider).selected!;
    setState(() { _running = true; _result = null; });
    try {
      final api = ref.read(apiServiceProvider);
      final p = _shellQuote(apk.path);
      final cmdMap = {
        'permissions': 'androguard permissions -i $p',
        'activities': 'androguard activities -i $p',
        'services': 'androguard services -i $p',
        'receivers': 'androguard receivers -i $p',
        'providers': 'androguard providers -i $p',
        'manifest': 'androaxml -i $p',
      };
      final res = await api.shellCommand(cmdMap[action]!);
      setState(() { _result = res['output']?.toString() ?? 'No output'; _running = false; });
    } catch (e) {
      setState(() { _result = 'Error: $e'; _running = false; });
    }
  }
}
