import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/providers/apk_provider.dart';
import '../../../core/services/api_service.dart';

class DiffView extends ConsumerStatefulWidget {
  const DiffView({super.key});

  @override
  ConsumerState<DiffView> createState() => _DiffViewState();
}

class _DiffViewState extends ConsumerState<DiffView> {
  bool _running = false;
  Map<String, dynamic>? _data;
  String? _targetId;

  Future<void> _runDiff(String oldId, String newId) async {
    setState(() { _running = true; _data = null; });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.diffAPKs(oldId, newId);
      setState(() { _data = res; _running = false; });
    } catch (e) {
      setState(() { _data = {'error': e.toString()}; _running = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final state = ref.watch(apkProvider);
    final currentApk = state.selected!;
    final otherApks = state.apks.where((a) => a.path != currentApk.path).toList();

    if (otherApks.isEmpty) {
      return Center(
        child: Text('Upload at least 2 APKs to compare versions.',
            style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Text('Compare: ', style: theme.textTheme.bodySmall),
              const SizedBox(width: 8),
              Expanded(
                child: DropdownMenu<String>(
                  initialSelection: _targetId,
                  expandedInsets: EdgeInsets.zero,
                  requestFocusOnTap: false,
                  label: const Text('Compare with...', style: TextStyle(fontSize: 12)),
                  textStyle: const TextStyle(fontSize: 12),
                  inputDecorationTheme: const InputDecorationTheme(
                    border: OutlineInputBorder(),
                    isDense: true,
                    contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  ),
                  dropdownMenuEntries: otherApks.map((a) => DropdownMenuEntry(
                    value: a.id ?? '',
                    label: a.packageName.isEmpty ? a.path.split('/').last : '${a.packageName} v${a.versionName}',
                  )).toList(),
                  onSelected: (v) => setState(() => _targetId = v),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                onPressed: (_running || _targetId == null || (currentApk.id ?? '').isEmpty)
                    ? null
                    : () => _runDiff(currentApk.id!, _targetId!),
                icon: _running
                    ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.compare_arrows, size: 16),
                label: Text(_running ? 'Comparing...' : 'Compare'),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: _data == null
              ? Center(
                  child: Text('Select another APK version and click Compare.',
                      style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
                )
              : _data!.containsKey('error')
                  ? Center(
                      child: SelectableText(_data!['error'].toString(),
                          style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
                    )
                  : SingleChildScrollView(
                      padding: const EdgeInsets.all(16),
                      child: _renderDiffResult(_data!, theme),
                    ),
        ),
      ],
    );
  }

  Widget _renderDiffResult(Map<String, dynamic> data, ThemeData theme) {
    final summary = data['summary'] as Map<String, dynamic>? ?? {};
    final riskDelta = (summary['risk_delta'] as num?)?.toInt() ?? 0;

    Widget diffSection(String title, IconData icon, List? added, List? removed) {
      final addedList = (added ?? []).cast<String>();
      final removedList = (removed ?? []).cast<String>();
      if (addedList.isEmpty && removedList.isEmpty) return const SizedBox.shrink();
      return Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, size: 14),
                const SizedBox(width: 6),
                Text(title, style: theme.textTheme.labelLarge),
                const SizedBox(width: 8),
                if (addedList.isNotEmpty)
                  Text('+${addedList.length}', style: const TextStyle(fontSize: 11, color: Colors.green, fontWeight: FontWeight.w600)),
                if (removedList.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(left: 6),
                    child: Text('-${removedList.length}', style: TextStyle(fontSize: 11, color: theme.colorScheme.error, fontWeight: FontWeight.w600)),
                  ),
              ],
            ),
            const SizedBox(height: 6),
            ...addedList.take(20).map((item) => Padding(
              padding: const EdgeInsets.symmetric(vertical: 1),
              child: Row(
                children: [
                  const Text('+ ', style: TextStyle(color: Colors.green, fontFamily: 'monospace', fontSize: 11)),
                  Expanded(child: SelectableText(item, style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', fontSize: 11))),
                ],
              ),
            )),
            ...removedList.take(20).map((item) => Padding(
              padding: const EdgeInsets.symmetric(vertical: 1),
              child: Row(
                children: [
                  Text('- ', style: TextStyle(color: theme.colorScheme.error, fontFamily: 'monospace', fontSize: 11)),
                  Expanded(child: SelectableText(item, style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', fontSize: 11))),
                ],
              ),
            )),
          ],
        ),
      );
    }

    final perms = data['permissions'] as Map<String, dynamic>? ?? {};
    final components = data['components'] as Map<String, dynamic>? ?? {};
    final files = data['files'] as Map<String, dynamic>? ?? {};
    final nativeLibs = data['native_libs'] as Map<String, dynamic>? ?? {};
    final sdks = data['sdks'] as Map<String, dynamic>? ?? {};

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text('Risk Delta: ', style: theme.textTheme.titleSmall),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                color: (riskDelta > 0 ? Colors.red : riskDelta < 0 ? Colors.green : Colors.grey).withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                riskDelta > 0 ? '+$riskDelta' : '$riskDelta',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: riskDelta > 0 ? Colors.red : riskDelta < 0 ? Colors.green : Colors.grey,
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        diffSection('Permissions', Icons.security, perms['added'] as List?, perms['removed'] as List?),
        diffSection('Components', Icons.widgets, components['added'] as List?, components['removed'] as List?),
        diffSection('Native Libraries', Icons.memory, nativeLibs['added'] as List?, nativeLibs['removed'] as List?),
        diffSection('SDKs', Icons.extension, sdks['added'] as List?, sdks['removed'] as List?),
        if (files['added'] != null || files['removed'] != null || files['changed'] != null) ...[
          Row(
            children: [
              const Icon(Icons.folder, size: 14),
              const SizedBox(width: 6),
              Text('Files', style: theme.textTheme.labelLarge),
              const SizedBox(width: 8),
              if ((files['added'] as List?)?.isNotEmpty ?? false)
                Text('+${(files['added'] as List).length}', style: const TextStyle(fontSize: 11, color: Colors.green, fontWeight: FontWeight.w600)),
              if ((files['removed'] as List?)?.isNotEmpty ?? false)
                Padding(
                  padding: const EdgeInsets.only(left: 6),
                  child: Text('-${(files['removed'] as List).length}', style: TextStyle(fontSize: 11, color: theme.colorScheme.error, fontWeight: FontWeight.w600)),
                ),
              if ((files['changed'] as List?)?.isNotEmpty ?? false)
                Padding(
                  padding: const EdgeInsets.only(left: 6),
                  child: Text('~${(files['changed'] as List).length}', style: const TextStyle(fontSize: 11, color: Colors.orange, fontWeight: FontWeight.w600)),
                ),
            ],
          ),
          const SizedBox(height: 6),
        ],
      ],
    );
  }
}
