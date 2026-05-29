import 'package:flutter/material.dart';

Widget renderAnalyzer(
    String type, Map<String, dynamic> data, ThemeData theme) {
  switch (type) {
    case 'manifest':
      return renderManifest(data, theme);
    case 'certificate':
      return renderCertificate(data, theme);
    case 'risk':
      return renderRisk(data, theme);
    case 'code':
      return renderCode(data, theme);
    case 'sdk':
      return renderSDK(data, theme);
    case 'strings':
      return renderStrings(data, theme);
    case 'antidetect':
      return renderAntiDetect(data, theme);
    default:
      return Text('Unknown analyzer: $type',
          style: theme.textTheme.bodySmall);
  }
}

Widget renderManifest(Map<String, dynamic> data, ThemeData theme) {
  final perms = (data['permissions'] as List?)?.cast<String>() ?? const [];
  final activities = (data['activities'] as List?) ?? const [];
  final services = (data['services'] as List?) ?? const [];
  final receivers = (data['receivers'] as List?) ?? const [];
  final providers = (data['providers'] as List?) ?? const [];
  final flags = <Widget>[];
  void addFlag(String label, bool? on, {bool danger = false}) {
    if (on == true) {
      flags.add(Chip(
        label: Text(label, style: const TextStyle(fontSize: 11)),
        backgroundColor: danger
            ? theme.colorScheme.error.withValues(alpha: 0.12)
            : theme.colorScheme.primary.withValues(alpha: 0.12),
        visualDensity: VisualDensity.compact,
      ));
    }
  }

  addFlag('debuggable', data['debuggable'] as bool?, danger: true);
  addFlag('allowBackup', data['allow_backup'] as bool?, danger: true);
  addFlag('cleartextTraffic', data['uses_cleartext_traffic'] as bool?,
      danger: true);

  return Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Wrap(spacing: 8, runSpacing: 4, children: [
        if (data['package'] != null)
          kvChip('package', data['package'].toString(), theme),
        if (data['version_name'] != null)
          kvChip('versionName', data['version_name'].toString(), theme),
        if (data['version_code'] != null && data['version_code'] != 0)
          kvChip('versionCode', data['version_code'].toString(), theme),
        if (data['min_sdk'] != null && data['min_sdk'] != 0)
          kvChip('minSdk', data['min_sdk'].toString(), theme),
        if (data['target_sdk'] != null && data['target_sdk'] != 0)
          kvChip('targetSdk', data['target_sdk'].toString(), theme),
        ...flags,
      ]),
      const SizedBox(height: 12),
      if (perms.isNotEmpty) ...[
        Text('Permissions (${perms.length})',
            style: theme.textTheme.labelLarge),
        const SizedBox(height: 6),
        Wrap(
          spacing: 6,
          runSpacing: 4,
          children: perms
              .map((p) => Chip(
                  label: Text(p, style: const TextStyle(fontSize: 10)),
                  visualDensity: VisualDensity.compact))
              .toList(),
        ),
        const SizedBox(height: 12),
      ],
      componentList('Activities', activities, theme),
      componentList('Services', services, theme),
      componentList('Receivers', receivers, theme),
      componentList('Providers', providers, theme),
    ],
  );
}

Widget componentList(String title, List items, ThemeData theme) {
  if (items.isEmpty) return const SizedBox.shrink();
  return Padding(
    padding: const EdgeInsets.only(bottom: 12),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('$title (${items.length})', style: theme.textTheme.labelLarge),
        const SizedBox(height: 6),
        ...items.take(15).map((c) {
          final m = c as Map<String, dynamic>;
          final exported = m['exported'];
          return Padding(
            padding: const EdgeInsets.symmetric(vertical: 2),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (m['is_launcher'] == true)
                  const Padding(
                    padding: EdgeInsets.only(top: 2, right: 4),
                    child: Icon(Icons.star, size: 12, color: Colors.amber),
                  ),
                if (exported == true)
                  Padding(
                    padding: const EdgeInsets.only(top: 2, right: 4),
                    child: Icon(Icons.public,
                        size: 12, color: theme.colorScheme.error),
                  ),
                Expanded(
                  child: SelectableText(
                    (m['name'] ?? '').toString(),
                    style: theme.textTheme.bodySmall
                        ?.copyWith(fontFamily: 'monospace'),
                  ),
                ),
              ],
            ),
          );
        }),
        if (items.length > 15)
          Text('… and ${items.length - 15} more',
              style: theme.textTheme.bodySmall),
      ],
    ),
  );
}

Widget renderCertificate(Map<String, dynamic> data, ThemeData theme) {
  return Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      if (data['debug'] == true)
        Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: Container(
            padding:
                const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: theme.colorScheme.error.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(
              'Signed with Android debug key',
              style: TextStyle(
                  color: theme.colorScheme.error, fontSize: 12),
            ),
          ),
        ),
      Wrap(spacing: 8, runSpacing: 4, children: [
        if (data['v1_verified'] != null)
          kvChip('v1', data['v1_verified'].toString(), theme),
        if (data['v2_verified'] != null)
          kvChip('v2', data['v2_verified'].toString(), theme),
        if (data['v3_verified'] != null)
          kvChip('v3', data['v3_verified'].toString(), theme),
      ]),
      const SizedBox(height: 8),
      if ((data['subject'] ?? '').toString().isNotEmpty)
        kv('Subject', data['subject'].toString(), theme),
      if ((data['issuer'] ?? '').toString().isNotEmpty)
        kv('Issuer', data['issuer'].toString(), theme),
      if ((data['sha1'] ?? '').toString().isNotEmpty)
        kv('SHA-1', data['sha1'].toString(), theme, mono: true),
      if ((data['sha256'] ?? '').toString().isNotEmpty)
        kv('SHA-256', data['sha256'].toString(), theme, mono: true),
      if ((data['algorithm'] ?? '').toString().isNotEmpty)
        kv('Algorithm', data['algorithm'].toString(), theme),
      if ((data['serial_hex'] ?? '').toString().isNotEmpty)
        kv('Serial', data['serial_hex'].toString(), theme, mono: true),
      if ((data['not_before'] ?? '').toString().isNotEmpty)
        kv('NotBefore', data['not_before'].toString(), theme),
      if ((data['not_after'] ?? '').toString().isNotEmpty)
        kv('NotAfter', data['not_after'].toString(), theme),
      if ((data['tool'] ?? '').toString().isNotEmpty)
        Padding(
          padding: const EdgeInsets.only(top: 4),
          child: Text('via ${data['tool']}',
              style:
                  theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
        ),
    ],
  );
}

Widget renderRisk(Map<String, dynamic> data, ThemeData theme) {
  final risks = (data['risks'] as List?) ?? const [];
  final score =
      (data['score'] is num) ? (data['score'] as num).toDouble() : 0.0;
  Color barColor = Colors.green;
  if (score >= 60) {
    barColor = theme.colorScheme.error;
  } else if (score >= 30) {
    barColor = Colors.orange;
  }
  return Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Row(children: [
        Text('Score: ${score.toStringAsFixed(0)} / 100',
            style: theme.textTheme.labelLarge),
        const SizedBox(width: 12),
        Expanded(
          child: ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: (score / 100).clamp(0.0, 1.0),
              color: barColor,
              backgroundColor: theme.dividerColor,
              minHeight: 6,
            ),
          ),
        ),
      ]),
      const SizedBox(height: 12),
      if (risks.isEmpty)
        Text('No risks detected.', style: theme.textTheme.bodySmall)
      else
        ...risks.map((r) {
          final m = r as Map<String, dynamic>;
          final level = (m['level'] ?? 'low').toString();
          Color color = Colors.green;
          if (level == 'high') color = theme.colorScheme.error;
          if (level == 'medium') color = Colors.orange;
          return Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  margin: const EdgeInsets.only(top: 4, right: 8),
                  padding: const EdgeInsets.symmetric(
                      horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(level.toUpperCase(),
                      style: TextStyle(
                          color: color,
                          fontSize: 10,
                          fontWeight: FontWeight.bold)),
                ),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text((m['title'] ?? m['code'] ?? '').toString(),
                          style: theme.textTheme.bodyMedium),
                      if ((m['description'] ?? '').toString().isNotEmpty)
                        Text(m['description'].toString(),
                            style: theme.textTheme.bodySmall
                                ?.copyWith(color: Colors.grey)),
                    ],
                  ),
                ),
              ],
            ),
          );
        }),
    ],
  );
}

Widget renderCode(Map<String, dynamic> data, ThemeData theme) {
  final endpoints = (data['endpoints'] as List?)?.cast<String>() ?? const [];
  final secrets = (data['secrets'] as List?) ?? const [];
  final dangerous = (data['dangerous_apis'] as List?) ?? const [];
  final scanned = data['files_scanned'] ?? 0;
  final truncated = data['truncated'] == true;
  return Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Row(children: [
        kvChip('files', scanned.toString(), theme),
        if (truncated)
          Padding(
            padding: const EdgeInsets.only(left: 6),
            child: Chip(
              label:
                  const Text('truncated', style: TextStyle(fontSize: 10)),
              backgroundColor: Colors.orange.withValues(alpha: 0.2),
              visualDensity: VisualDensity.compact,
            ),
          ),
      ]),
      const SizedBox(height: 8),
      expandable(
          'Endpoints (${endpoints.length})',
          endpoints
              .take(50)
              .map(
                (e) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 1),
                  child: SelectableText(e,
                      style: theme.textTheme.bodySmall
                          ?.copyWith(fontFamily: 'monospace')),
                ),
              )
              .toList(),
          theme),
      expandable(
        'Secrets / Credentials (${secrets.length})',
        secrets.take(50).map((s) => findingRow(s, theme)).toList(),
        theme,
        danger: secrets.isNotEmpty,
      ),
      expandable(
        'Dangerous APIs (${dangerous.length})',
        dangerous.take(50).map((s) => findingRow(s, theme)).toList(),
        theme,
        danger: dangerous.isNotEmpty,
      ),
    ],
  );
}

Widget findingRow(dynamic raw, ThemeData theme) {
  final m = raw as Map<String, dynamic>;
  return Padding(
    padding: const EdgeInsets.symmetric(vertical: 2),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(children: [
          Container(
            padding:
                const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
            decoration: BoxDecoration(
              color: theme.colorScheme.primary.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(3),
            ),
            child: Text((m['kind'] ?? m['pattern'] ?? '').toString(),
                style: const TextStyle(fontSize: 10)),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: SelectableText(
              '${m['file'] ?? ''}:${m['line'] ?? ''}',
              style: theme.textTheme.bodySmall
                  ?.copyWith(fontFamily: 'monospace', color: Colors.grey),
            ),
          ),
        ]),
        if ((m['value'] ?? '').toString().isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(left: 4, top: 2),
            child: SelectableText(
              m['value'].toString(),
              style: theme.textTheme.bodySmall
                  ?.copyWith(fontFamily: 'monospace'),
              maxLines: 3,
            ),
          ),
      ],
    ),
  );
}

Widget renderSDK(Map<String, dynamic> data, ThemeData theme) {
  final sdks = (data['sdks'] as List?) ?? const [];
  if (sdks.isEmpty) {
    return Text('No known SDKs detected.', style: theme.textTheme.bodySmall);
  }
  final byCategory = <String, List<Map<String, dynamic>>>{};
  for (final s in sdks) {
    final m = s as Map<String, dynamic>;
    byCategory
        .putIfAbsent((m['category'] ?? 'other').toString(), () => [])
        .add(m);
  }
  return Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: byCategory.entries
        .map((e) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(e.key, style: theme.textTheme.labelLarge),
                  const SizedBox(height: 4),
                  Wrap(
                    spacing: 6,
                    runSpacing: 4,
                    children: e.value
                        .map((m) => Chip(
                              label: Text(m['name'].toString(),
                                  style: const TextStyle(fontSize: 11)),
                              visualDensity: VisualDensity.compact,
                            ))
                        .toList(),
                  ),
                ],
              ),
            ))
        .toList(),
  );
}

Widget renderStrings(Map<String, dynamic> data, ThemeData theme) {
  final firebase = data['firebase'] as Map<String, dynamic>?;
  final domains = (data['domains'] as List?)?.cast<Map<String, dynamic>>() ?? [];
  final ips = (data['ips'] as List?)?.cast<Map<String, dynamic>>() ?? [];
  final crypto = (data['crypto_usage'] as List?)?.cast<Map<String, dynamic>>() ?? [];
  final configs = (data['configs'] as List?)?.cast<Map<String, dynamic>>() ?? [];
  final filesScanned = data['files_scanned'] ?? 0;

  return Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      kvChip('files scanned', filesScanned.toString(), theme),
      const SizedBox(height: 12),
      if (firebase != null) ...[
        Text('Firebase Config', style: theme.textTheme.labelLarge),
        const SizedBox(height: 6),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
            borderRadius: BorderRadius.circular(6),
            border: const Border(left: BorderSide(color: Colors.orange, width: 3)),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if ((firebase['project_id'] ?? '').toString().isNotEmpty)
                kv('Project', firebase['project_id'].toString(), theme, mono: true),
              if ((firebase['app_id'] ?? '').toString().isNotEmpty)
                kv('App ID', firebase['app_id'].toString(), theme, mono: true),
              if ((firebase['api_key'] ?? '').toString().isNotEmpty)
                kv('API Key', firebase['api_key'].toString(), theme, mono: true),
              if ((firebase['storage_bucket'] ?? '').toString().isNotEmpty)
                kv('Bucket', firebase['storage_bucket'].toString(), theme, mono: true),
              if ((firebase['database_url'] ?? '').toString().isNotEmpty)
                kv('DB URL', firebase['database_url'].toString(), theme, mono: true),
            ],
          ),
        ),
        const SizedBox(height: 12),
      ],
      if (crypto.isNotEmpty) ...[
        expandable(
          'Crypto Usage (${crypto.length})',
          crypto.map((c) {
            final strength = (c['strength'] ?? '').toString();
            Color color = Colors.green;
            if (strength == 'weak') color = Colors.red;
            if (strength == 'moderate') color = Colors.orange;
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 3),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                    decoration: BoxDecoration(
                      color: color.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Text(strength.toUpperCase(),
                        style: TextStyle(fontSize: 9, color: color, fontWeight: FontWeight.bold)),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(c['algorithm']?.toString() ?? '',
                            style: theme.textTheme.bodySmall?.copyWith(fontWeight: FontWeight.w600)),
                        if ((c['file'] ?? '').toString().isNotEmpty)
                          Text('${c['file']}:${c['line'] ?? ''}',
                              style: theme.textTheme.bodySmall?.copyWith(
                                  fontFamily: 'monospace', fontSize: 10, color: Colors.grey)),
                      ],
                    ),
                  ),
                ],
              ),
            );
          }).toList(),
          theme,
          danger: crypto.any((c) => c['strength'] == 'weak'),
        ),
      ],
      if (domains.isNotEmpty)
        expandable(
          'Domains (${domains.length})',
          groupByCategory(domains, 'host', theme),
          theme,
        ),
      if (ips.isNotEmpty)
        expandable(
          'IPs (${ips.length})',
          ips.map((ip) => Padding(
            padding: const EdgeInsets.symmetric(vertical: 1),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.primary.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(ip['category']?.toString() ?? '',
                      style: const TextStyle(fontSize: 9)),
                ),
                const SizedBox(width: 8),
                SelectableText(ip['ip']?.toString() ?? '',
                    style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace')),
              ],
            ),
          )).toList(),
          theme,
        ),
      if (configs.isNotEmpty)
        expandable(
          'Config Findings (${configs.length})',
          configs.map((c) => Padding(
            padding: const EdgeInsets.symmetric(vertical: 2),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                      decoration: BoxDecoration(
                        color: Colors.orange.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(3),
                      ),
                      child: Text(c['type']?.toString() ?? '',
                          style: const TextStyle(fontSize: 9)),
                    ),
                    const SizedBox(width: 6),
                    Expanded(
                      child: SelectableText('${c['key']}: ${c['value']}',
                          style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace')),
                    ),
                  ],
                ),
                if ((c['file'] ?? '').toString().isNotEmpty)
                  Text(c['file'].toString(),
                      style: theme.textTheme.bodySmall?.copyWith(fontSize: 10, color: Colors.grey)),
              ],
            ),
          )).toList(),
          theme,
          danger: true,
        ),
    ],
  );
}

List<Widget> groupByCategory(List<Map<String, dynamic>> items, String valueKey, ThemeData theme) {
  final grouped = <String, List<String>>{};
  for (final item in items) {
    final cat = (item['category'] ?? 'unknown').toString();
    grouped.putIfAbsent(cat, () => []).add(item[valueKey]?.toString() ?? '');
  }
  return grouped.entries.map((e) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(e.key, style: theme.textTheme.labelSmall?.copyWith(fontWeight: FontWeight.w600)),
        const SizedBox(height: 2),
        Wrap(
          spacing: 6,
          runSpacing: 4,
          children: e.value.map((v) => Chip(
            label: Text(v, style: const TextStyle(fontSize: 10)),
            visualDensity: VisualDensity.compact,
            materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
          )).toList(),
        ),
      ],
    ),
  )).toList();
}

Widget renderAntiDetect(Map<String, dynamic> data, ThemeData theme) {
  final summary = data['summary'] as Map<String, dynamic>? ?? {};
  final protectionLevel = (summary['protection_level'] ?? 'none').toString();
  final totalFindings = (summary['total_findings'] as num?)?.toInt() ?? 0;

  Color levelColor() {
    switch (protectionLevel) {
      case 'strong': return Colors.green.shade700;
      case 'moderate': return Colors.orange;
      case 'basic': return Colors.amber.shade700;
      default: return Colors.red;
    }
  }

  Widget detectionSection(String title, IconData icon, List? findings, bool? detected) {
    final items = findings?.cast<Map<String, dynamic>>() ?? [];
    if (items.isEmpty) {
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(
          children: [
            Icon(icon, size: 14, color: Colors.grey),
            const SizedBox(width: 8),
            Text(title, style: theme.textTheme.bodySmall),
            const Spacer(),
            Icon(detected == true ? Icons.check_circle : Icons.cancel,
                size: 14, color: detected == true ? Colors.green : Colors.red.shade300),
            const SizedBox(width: 4),
            Text(detected == true ? 'Detected' : 'Not found',
                style: TextStyle(fontSize: 11, color: detected == true ? Colors.green : Colors.red.shade300)),
          ],
        ),
      );
    }
    return expandable(
      '$title (${items.length})',
      items.map((f) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                  decoration: BoxDecoration(
                    color: Colors.green.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(f['pattern']?.toString() ?? '',
                      style: const TextStyle(fontSize: 9, fontWeight: FontWeight.w600)),
                ),
                const SizedBox(width: 6),
                if ((f['confidence'] ?? '').toString().isNotEmpty)
                  Text(f['confidence'].toString(),
                      style: TextStyle(fontSize: 10, color: Colors.grey.shade600)),
              ],
            ),
            if ((f['evidence'] ?? '').toString().isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: SelectableText(f['evidence'].toString(),
                    style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', fontSize: 10)),
              ),
            if ((f['file'] ?? '').toString().isNotEmpty)
              Text('${f['file']}:${f['line'] ?? ''}',
                  style: theme.textTheme.bodySmall?.copyWith(fontSize: 10, color: Colors.grey)),
          ],
        ),
      )).toList(),
      theme,
    );
  }

  return Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Row(children: [
        Text('Protection Level: ', style: theme.textTheme.titleSmall),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
          decoration: BoxDecoration(
            color: levelColor().withValues(alpha: 0.15),
            borderRadius: BorderRadius.circular(4),
          ),
          child: Text(protectionLevel.toUpperCase(),
              style: TextStyle(fontSize: 11, color: levelColor(), fontWeight: FontWeight.w600)),
        ),
        const SizedBox(width: 12),
        Text('$totalFindings findings', style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
      ]),
      const SizedBox(height: 12),
      detectionSection('Root Detection', Icons.admin_panel_settings,
          data['root_detection'], summary['has_root_detection']),
      detectionSection('Frida Detection', Icons.bug_report,
          data['frida_detection'], summary['has_frida_detection']),
      detectionSection('Emulator Detection', Icons.phone_android,
          data['emulator_detection'], summary['has_emulator_detection']),
      detectionSection('Debug Detection', Icons.developer_mode,
          data['debug_detection'], summary['has_debug_detection']),
      detectionSection('Tamper Detection', Icons.security,
          data['tamper_detection'], summary['has_tamper_detection']),
    ],
  );
}

Widget kvChip(String k, String v, ThemeData theme) {
  return Chip(
    label: Text('$k: $v', style: const TextStyle(fontSize: 11)),
    visualDensity: VisualDensity.compact,
  );
}

Widget kv(String k, String v, ThemeData theme, {bool mono = false}) {
  return Padding(
    padding: const EdgeInsets.symmetric(vertical: 2),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 80,
          child: Text(k,
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: Colors.grey)),
        ),
        Expanded(
          child: SelectableText(
            v,
            style: theme.textTheme.bodySmall
                ?.copyWith(fontFamily: mono ? 'monospace' : null),
          ),
        ),
      ],
    ),
  );
}

Widget expandable(String title, List<Widget> children, ThemeData theme,
    {bool danger = false}) {
  return Theme(
    data: theme.copyWith(dividerColor: Colors.transparent),
    child: ExpansionTile(
      tilePadding: EdgeInsets.zero,
      childrenPadding: const EdgeInsets.only(left: 8, bottom: 8),
      title: Text(title,
          style: theme.textTheme.labelLarge?.copyWith(
              color: danger ? theme.colorScheme.error : null)),
      children: children.isEmpty
          ? [Text('—', style: theme.textTheme.bodySmall)]
          : children,
    ),
  );
}
