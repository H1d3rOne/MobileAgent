import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/providers/apk_provider.dart';
import '../../../core/services/api_service.dart';

class CallGraphView extends ConsumerStatefulWidget {
  const CallGraphView({super.key});

  @override
  ConsumerState<CallGraphView> createState() => _CallGraphViewState();
}

class _CallGraphViewState extends ConsumerState<CallGraphView> {
  bool _running = false;
  Map<String, dynamic>? _data;

  @override
  void initState() {
    super.initState();
    final apk = ref.read(apkProvider).selected;
    if (apk != null && _data == null) _load(apk.id);
  }

  Future<void> _load(String? id) async {
    if (id == null) {
      setState(() => _data = {'error': 'APK has no ID'});
      return;
    }
    setState(() { _running = true; _data = null; });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.callGraph(id);
      setState(() { _data = res; _running = false; });
    } catch (e) {
      setState(() { _data = {'error': e.toString()}; _running = false; });
    }
  }

  Widget _infoChip(String label, ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.only(left: 6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(4),
        ),
        child: Text(label, style: TextStyle(fontSize: 10, color: theme.colorScheme.onSurface.withValues(alpha: 0.7))),
      ),
    );
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
            Text('Building call graph from smali...'),
          ],
        ),
      );
    }

    if (_data == null) {
      return Center(
        child: Text('Click Call Graph to analyze method call relationships.',
            style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
      );
    }

    if (_data!.containsKey('error')) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline, size: 36, color: theme.colorScheme.error),
              const SizedBox(height: 8),
              SelectableText(_data!['error'].toString(),
                  style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
            ],
          ),
        ),
      );
    }

    final stats = _data!['stats'] as Map<String, dynamic>? ?? {};
    final hotMethods = (_data!['hot_methods'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final paths = (_data!['paths'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final entryPoints = (_data!['entry_points'] as List?)?.cast<String>() ?? [];
    final nodes = (_data!['nodes'] as List?)?.length ?? 0;
    final edges = (_data!['edges'] as List?)?.length ?? 0;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Text('Call Graph', style: theme.textTheme.titleMedium),
              const Spacer(),
              _infoChip('$nodes nodes', theme),
              _infoChip('$edges edges', theme),
              if (stats['classes'] != null)
                _infoChip('${stats['classes']} classes', theme),
              IconButton(
                icon: const Icon(Icons.refresh, size: 16),
                tooltip: 'Rebuild',
                onPressed: () {
                  final apk = ref.read(apkProvider).selected;
                  if (apk != null) _load(apk.id);
                },
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (paths.isNotEmpty) ...[
                  Text('Data Flow Paths (source → sink)', style: theme.textTheme.labelLarge),
                  const SizedBox(height: 8),
                  ...paths.take(20).map((p) {
                    final risk = (p['risk'] ?? 'low').toString();
                    Color riskColor = Colors.green;
                    if (risk == 'high') riskColor = Colors.red;
                    if (risk == 'medium') riskColor = Colors.orange;
                    final pathSteps = (p['path'] as List?)?.cast<String>() ?? [];
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          border: Border(left: BorderSide(color: riskColor, width: 3)),
                          color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                                  decoration: BoxDecoration(
                                    color: riskColor.withValues(alpha: 0.15),
                                    borderRadius: BorderRadius.circular(3),
                                  ),
                                  child: Text(risk.toUpperCase(),
                                      style: TextStyle(fontSize: 9, color: riskColor, fontWeight: FontWeight.bold)),
                                ),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: Text('${p['source']} → ${p['sink']}',
                                      style: theme.textTheme.bodySmall?.copyWith(fontWeight: FontWeight.w600)),
                                ),
                              ],
                            ),
                            if (pathSteps.isNotEmpty) ...[
                              const SizedBox(height: 6),
                              ...pathSteps.map((step) => Padding(
                                padding: const EdgeInsets.only(left: 12, top: 2),
                                child: Row(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text('→ ', style: TextStyle(fontSize: 10, color: Colors.grey.shade600)),
                                    Expanded(
                                      child: SelectableText(step,
                                          style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', fontSize: 10)),
                                    ),
                                  ],
                                ),
                              )),
                            ],
                          ],
                        ),
                      ),
                    );
                  }),
                  const SizedBox(height: 16),
                ],
                if (hotMethods.isNotEmpty) ...[
                  Text('Hot Methods (high connectivity)', style: theme.textTheme.labelLarge),
                  const SizedBox(height: 8),
                  Wrap(
                    spacing: 6,
                    runSpacing: 6,
                    children: hotMethods.take(30).map((m) {
                      final id = m['id']?.toString() ?? '';
                      final inDeg = m['in_degree'] ?? 0;
                      final outDeg = m['out_degree'] ?? 0;
                      return Tooltip(
                        message: 'in: $inDeg, out: $outDeg',
                        child: Chip(
                          label: Text(id.split(';').last.split('(').first,
                              style: const TextStyle(fontSize: 10, fontFamily: 'monospace')),
                          visualDensity: VisualDensity.compact,
                          materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                        ),
                      );
                    }).toList(),
                  ),
                  const SizedBox(height: 16),
                ],
                if (entryPoints.isNotEmpty) ...[
                  Text('Entry Points', style: theme.textTheme.labelLarge),
                  const SizedBox(height: 8),
                  ...entryPoints.take(20).map((ep) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: SelectableText(ep,
                        style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', fontSize: 11)),
                  )),
                ],
              ],
            ),
          ),
        ),
      ],
    );
  }
}
