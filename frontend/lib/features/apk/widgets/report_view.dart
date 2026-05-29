import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/providers/apk_provider.dart';
import '../../../core/services/api_service.dart';

class ReportView extends ConsumerStatefulWidget {
  const ReportView({super.key});

  @override
  ConsumerState<ReportView> createState() => _ReportViewState();
}

class _ReportViewState extends ConsumerState<ReportView> {
  bool _running = false;
  Map<String, dynamic>? _data;

  @override
  void initState() {
    super.initState();
    final apk = ref.read(apkProvider).selected;
    if (apk != null && _data == null) _generate(apk.id);
  }

  Future<void> _generate(String? id) async {
    if (id == null) {
      setState(() => _data = {'error': 'APK has no ID'});
      return;
    }
    setState(() { _running = true; _data = null; });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.generateReport(id);
      setState(() { _data = res; _running = false; });
    } catch (e) {
      setState(() { _data = {'error': e.toString()}; _running = false; });
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
            Text('Generating security report...'),
          ],
        ),
      );
    }

    if (_data == null) {
      return Center(
        child: Text('Click Report to generate a full security assessment.',
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
              Text('Report generation failed', style: theme.textTheme.titleMedium),
              const SizedBox(height: 4),
              SelectableText(_data!['error'].toString(),
                  style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
            ],
          ),
        ),
      );
    }

    final score = (_data!['overall_score'] as num?)?.toDouble() ?? 0;
    final riskLevel = _data!['risk_level']?.toString() ?? 'unknown';
    final sections = (_data!['sections'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final stats = _data!['statistics'] as Map<String, dynamic>? ?? {};

    Color riskColor() {
      switch (riskLevel) {
        case 'critical': return Colors.red.shade700;
        case 'high': return Colors.red;
        case 'medium': return Colors.orange;
        case 'low': return Colors.green;
        default: return Colors.grey;
      }
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Text('Security Score: ', style: theme.textTheme.titleMedium),
              Text('${score.toInt()}/100',
                  style: theme.textTheme.titleMedium?.copyWith(
                      color: riskColor(), fontWeight: FontWeight.bold)),
              const SizedBox(width: 12),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  color: riskColor().withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(riskLevel.toUpperCase(),
                    style: TextStyle(fontSize: 11, color: riskColor(), fontWeight: FontWeight.w600)),
              ),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.copy, size: 16),
                tooltip: 'Copy report',
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: _formatText()));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Report copied'), duration: Duration(seconds: 1)),
                  );
                },
              ),
              IconButton(
                icon: const Icon(Icons.refresh, size: 16),
                tooltip: 'Regenerate',
                onPressed: () {
                  final apk = ref.read(apkProvider).selected;
                  if (apk != null) _generate(apk.id);
                },
              ),
            ],
          ),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Wrap(
            spacing: 12,
            runSpacing: 4,
            children: [
              _statChip('Permissions', '${stats['total_permissions'] ?? 0}', theme),
              _statChip('Dangerous', '${stats['dangerous_permissions'] ?? 0}', theme, color: Colors.orange),
              _statChip('Exported', '${stats['exported_components'] ?? 0}', theme),
              _statChip('Secrets', '${stats['secrets_found'] ?? 0}', theme, color: Colors.red),
              _statChip('APIs', '${stats['dangerous_apis'] ?? 0}', theme, color: Colors.orange),
              _statChip('SDKs', '${stats['sdk_count'] ?? 0}', theme),
            ],
          ),
        ),
        const SizedBox(height: 8),
        const Divider(height: 1),
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.all(12),
            itemCount: sections.length,
            itemBuilder: (ctx, i) {
              final s = sections[i];
              final status = s['status']?.toString() ?? 'info';
              final title = s['title']?.toString() ?? '';
              final summary = s['summary']?.toString() ?? '';
              final category = s['category']?.toString() ?? '';
              final details = (s['details'] as List?)?.cast<String>() ?? [];

              Color statusColor() {
                switch (status) {
                  case 'pass': return Colors.green;
                  case 'warn': return Colors.orange;
                  case 'fail': return Colors.red;
                  default: return Colors.grey;
                }
              }

              IconData statusIcon() {
                switch (status) {
                  case 'pass': return Icons.check_circle;
                  case 'warn': return Icons.warning_amber;
                  case 'fail': return Icons.cancel;
                  default: return Icons.info_outline;
                }
              }

              return Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Container(
                  decoration: BoxDecoration(
                    border: Border(left: BorderSide(color: statusColor(), width: 3)),
                    color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  padding: const EdgeInsets.all(10),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(statusIcon(), size: 14, color: statusColor()),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(title,
                                style: theme.textTheme.bodyMedium?.copyWith(fontWeight: FontWeight.w600)),
                          ),
                          Text(category,
                              style: TextStyle(fontSize: 10, color: Colors.grey.shade600)),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(summary, style: theme.textTheme.bodySmall),
                      if (details.isNotEmpty) ...[
                        const SizedBox(height: 4),
                        ...details.map((d) => Padding(
                          padding: const EdgeInsets.only(left: 20, top: 2),
                          child: Text('• $d',
                              style: theme.textTheme.bodySmall?.copyWith(
                                  fontFamily: 'monospace', fontSize: 11, color: Colors.grey.shade700)),
                        )),
                      ],
                    ],
                  ),
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _statChip(String label, String value, ThemeData theme, {Color? color}) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text('$label: ', style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
        Text(value, style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: color)),
      ],
    );
  }

  String _formatText() {
    if (_data == null) return '';
    final score = (_data!['overall_score'] as num?)?.toDouble() ?? 0;
    final riskLevel = _data!['risk_level']?.toString() ?? 'unknown';
    final sections = (_data!['sections'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final buf = StringBuffer();
    buf.writeln('Security Report — Score: ${score.toInt()}/100 ($riskLevel)');
    buf.writeln('=' * 50);
    for (final s in sections) {
      final status = (s['status'] ?? 'info').toString().toUpperCase();
      buf.writeln('[$status] ${s['title']} — ${s['summary']}');
      final details = (s['details'] as List?)?.cast<String>() ?? [];
      for (final d in details) {
        buf.writeln('    • $d');
      }
    }
    return buf.toString();
  }
}
