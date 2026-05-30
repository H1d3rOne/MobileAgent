import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';

import '../../../core/services/api_service.dart';
import 'result_panel.dart';

// frida-based in-memory DEX dump: hooks the ART loader and writes every
// loaded DEX image to the app's files dir, defeating most runtime packers.
const _dexDumpScript = r'''
Java.perform(function () {
  function dumpRange(base, size, idx) {
    try {
      var dir = "/data/data/" + getPkg() + "/files";
      var path = dir + "/dump_" + idx + "_" + size + ".dex";
      var f = new File(path, "wb");
      f.write(Memory.readByteArray(base, size));
      f.flush(); f.close();
      send("[dexdump] wrote " + path);
    } catch (e) { send("[dexdump] write failed: " + e); }
  }
  function getPkg() {
    var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    return ctx.getPackageName();
  }
  // Hook DefineClass-time DEX images via libart OpenMemory / DexFile ctor.
  var n = 0;
  ["_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_",
   "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_PNS0_12VerifyResultE"]
    .forEach(function (sym) {
      var p = Module.findExportByName("libart.so", sym);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function (args) {
          try {
            var base = args[1];
            var size = args[2].toInt32();
            if (size > 0x20) dumpRange(base, size, n++);
          } catch (e) {}
        }
      });
    });
  send("[dexdump] hooks installed (" + n + " sites) — exercise the app to trigger DEX loads");
});
''';

class NetworkTab extends ConsumerStatefulWidget {
  const NetworkTab({super.key});

  @override
  ConsumerState<NetworkTab> createState() => _NetworkTabState();
}

class _NetworkTabState extends ConsumerState<NetworkTab> {
  String _subTab = 'proxy';

  // Proxy state
  final _portController = TextEditingController(text: '8080');
  bool _proxyRunning = false;
  String? _proxyResult;

  // Capture state
  bool _captureLoading = false;
  Map<String, dynamic>? _captureResult;

  // Frida state
  List<Map<String, dynamic>>? _scripts;
  List<String>? _categories;
  String? _selectedCategory;
  String? _selectedScript;
  bool _scriptsLoading = false;
  bool _fridaRunning = false;
  String? _fridaRunOutput;
  bool _dumping = false;
  final _serialController = TextEditingController();
  final _targetController = TextEditingController();

  @override
  void dispose() {
    _portController.dispose();
    _serialController.dispose();
    _targetController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Row(children: [
            SegmentedButton<String>(
              segments: const [
                ButtonSegment(value: 'proxy', label: Text('Proxy', style: TextStyle(fontSize: 12)), icon: Icon(Icons.wifi_tethering, size: 14)),
                ButtonSegment(value: 'capture', label: Text('Capture', style: TextStyle(fontSize: 12)), icon: Icon(Icons.upload_file, size: 14)),
                ButtonSegment(value: 'frida', label: Text('Frida Scripts', style: TextStyle(fontSize: 12)), icon: Icon(Icons.code, size: 14)),
              ],
              selected: {_subTab},
              onSelectionChanged: (v) {
                setState(() => _subTab = v.first);
                if (v.first == 'frida' && _scripts == null && !_scriptsLoading) {
                  _loadScripts();
                }
              },
              style: const ButtonStyle(
                visualDensity: VisualDensity.compact,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
            ),
          ]),
        ),
        const Divider(height: 1),
        Expanded(
          child: switch (_subTab) {
            'proxy' => _buildProxy(theme),
            'capture' => _buildCapture(theme),
            _ => _buildFrida(theme),
          },
        ),
      ],
    );
  }

  // ── Proxy ──────────────────────────────────────────────────────────────────

  Widget _buildProxy(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(children: [
            SizedBox(
              width: 100,
              child: TextField(
                controller: _portController,
                decoration: const InputDecoration(
                  labelText: 'Port', hintText: '8080',
                  border: OutlineInputBorder(), isDense: true,
                  contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                ),
                keyboardType: TextInputType.number,
              ),
            ),
            const SizedBox(width: 8),
            FilledButton.icon(
              onPressed: _proxyRunning ? null : _startProxy,
              icon: const Icon(Icons.play_arrow, size: 16),
              label: const Text('Start'),
            ),
            const SizedBox(width: 6),
            OutlinedButton.icon(
              onPressed: _proxyRunning ? _stopProxy : null,
              icon: const Icon(Icons.stop, size: 16),
              label: const Text('Stop'),
            ),
          ]),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: _proxyResult == null && !_proxyRunning
                ? _buildInstructions(theme)
                : ResultPanel(
                    content: _proxyResult,
                    isRunning: _proxyRunning && _proxyResult == null,
                    isError: _proxyResult?.startsWith('Error') ?? false,
                    emptyHint: 'Proxy output will appear here',
                  ),
          ),
        ),
      ],
    );
  }

  Widget _buildInstructions(ThemeData theme) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
      ),
      child: SelectableText(
        'HTTPS traffic interception (via mitmproxy)\n\n'
        '1. Start proxy (default port 8080)\n'
        '2. Set device WiFi proxy to this computer\'s IP:port\n'
        '3. Visit http://mitm.it on device to install CA cert\n'
        '4. For SSL pinning bypass, use Frida scripts\n'
        '5. View traffic at http://localhost:8081 (mitmweb)',
        style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', height: 1.8),
      ),
    );
  }

  Future<void> _startProxy() async {
    final port = _portController.text.trim();
    if (port.isEmpty) {
      setState(() => _proxyResult = 'Error: port is required');
      return;
    }
    setState(() { _proxyResult = 'Starting mitmproxy on port $port...'; });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.shellCommand('nohup mitmdump -p $port --set block_global=false >/tmp/mitmdump-$port.log 2>&1 & echo started pid \$!');
      setState(() {
        _proxyRunning = true;
        _proxyResult = 'Proxy running on port $port\n${res['output'] ?? ''}'.trimRight();
      });
    } catch (e) {
      setState(() { _proxyResult = 'Error: $e'; _proxyRunning = false; });
    }
  }

  Future<void> _stopProxy() async {
    setState(() { _proxyResult = 'Stopping...'; });
    try {
      final api = ref.read(apiServiceProvider);
      await api.shellCommand('pkill -f mitmdump || true');
      setState(() { _proxyRunning = false; _proxyResult = 'Proxy stopped.'; });
    } catch (e) {
      setState(() => _proxyResult = 'Stop error: $e');
    }
  }

  // ── Capture ────────────────────────────────────────────────────────────────

  Widget _buildCapture(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(children: [
            FilledButton.tonalIcon(
              onPressed: _captureLoading ? null : _pickAndParse,
              icon: _captureLoading
                  ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.upload_file, size: 16),
              label: const Text('Upload HAR / mitmproxy dump'),
            ),
            if (_captureResult != null) ...[
              const SizedBox(width: 8),
              TextButton.icon(
                onPressed: () => setState(() => _captureResult = null),
                icon: const Icon(Icons.clear, size: 14),
                label: const Text('Clear'),
              ),
            ],
          ]),
        ),
        const Divider(height: 1),
        Expanded(
          child: _captureResult == null
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.cloud_upload_outlined, size: 48, color: Colors.grey[400]),
                      const SizedBox(height: 12),
                      Text('Upload a .har or mitmproxy text dump to analyze network traffic',
                          style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
                      const SizedBox(height: 4),
                      Text('Supports HAR (Chrome/Firefox export) and mitmproxy flow dumps',
                          style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey[500], fontSize: 11)),
                    ],
                  ),
                )
              : _buildCaptureResult(theme),
        ),
      ],
    );
  }

  Widget _buildCaptureResult(ThemeData theme) {
    final data = _captureResult!;
    final summary = data['summary'] as Map<String, dynamic>? ?? {};
    final requests = (data['requests'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final domains = (data['domains'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final endpoints = (data['api_endpoints'] as List?)?.cast<Map<String, dynamic>>() ?? [];

    return DefaultTabController(
      length: 3,
      child: Column(children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
          child: Row(children: [
            CaptureChip(label: '${summary['total_requests'] ?? 0} requests', icon: Icons.http),
            const SizedBox(width: 8),
            CaptureChip(label: '${summary['unique_hosts'] ?? 0} hosts', icon: Icons.dns),
            const SizedBox(width: 8),
            if (summary['has_https'] == true)
              const CaptureChip(label: 'HTTPS', icon: Icons.lock, color: Colors.green),
            if (summary['has_http'] == true) ...[
              const SizedBox(width: 8),
              const CaptureChip(label: 'HTTP', icon: Icons.lock_open, color: Colors.orange),
            ],
          ]),
        ),
        TabBar(
          isScrollable: true, tabAlignment: TabAlignment.start,
          labelStyle: const TextStyle(fontSize: 11),
          tabs: [
            Tab(text: 'Requests (${requests.length})'),
            Tab(text: 'Domains (${domains.length})'),
            Tab(text: 'Endpoints (${endpoints.length})'),
          ],
        ),
        Expanded(
          child: TabBarView(children: [
            _buildRequestsList(requests, theme),
            _buildDomainsList(domains, theme),
            _buildEndpointsList(endpoints, theme),
          ]),
        ),
      ]),
    );
  }

  Widget _buildRequestsList(List<Map<String, dynamic>> requests, ThemeData theme) {
    if (requests.isEmpty) return const Center(child: Text('No requests captured'));
    return ListView.builder(
      padding: const EdgeInsets.all(4),
      itemCount: requests.length,
      itemBuilder: (ctx, i) {
        final req = requests[i];
        final method = req['method']?.toString() ?? 'GET';
        final urlStr = req['url']?.toString() ?? '';
        final category = req['category']?.toString() ?? '';
        final status = req['status_code'] as int? ?? 0;
        final methodColor = _methodColor(method);

        return Padding(
          padding: const EdgeInsets.only(bottom: 2),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.2),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Row(children: [
              Container(
                width: 48,
                padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                decoration: BoxDecoration(
                  color: methodColor.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: Text(method, textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 9, fontWeight: FontWeight.w700, color: methodColor)),
              ),
              const SizedBox(width: 6),
              if (status > 0) ...[
                Text('$status', style: TextStyle(fontSize: 10,
                    color: status >= 400 ? Colors.red : Colors.grey[600],
                    fontWeight: FontWeight.w600)),
                const SizedBox(width: 6),
              ],
              Expanded(
                child: Text(urlStr, maxLines: 1, overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 11, fontFamily: 'monospace')),
              ),
              if (category.isNotEmpty)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                  decoration: BoxDecoration(
                    color: _categoryColor(category).withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(category, style: TextStyle(fontSize: 9, color: _categoryColor(category))),
                ),
            ]),
          ),
        );
      },
    );
  }

  Widget _buildDomainsList(List<Map<String, dynamic>> domains, ThemeData theme) {
    if (domains.isEmpty) return const Center(child: Text('No domains found'));
    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: domains.length,
      itemBuilder: (ctx, i) {
        final d = domains[i];
        final domain = d['domain']?.toString() ?? '';
        final count = d['count'] as int? ?? 0;
        final category = d['category']?.toString() ?? '';
        return ListTile(
          dense: true,
          visualDensity: const VisualDensity(vertical: -3),
          leading: Icon(Icons.dns, size: 16, color: _categoryColor(category)),
          title: Text(domain, style: const TextStyle(fontSize: 12, fontFamily: 'monospace')),
          trailing: Row(mainAxisSize: MainAxisSize.min, children: [
            if (category.isNotEmpty)
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                margin: const EdgeInsets.only(right: 8),
                decoration: BoxDecoration(
                  color: _categoryColor(category).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: Text(category, style: TextStyle(fontSize: 9, color: _categoryColor(category))),
              ),
            Text('$count', style: theme.textTheme.labelSmall?.copyWith(fontWeight: FontWeight.w600)),
          ]),
        );
      },
    );
  }

  Widget _buildEndpointsList(List<Map<String, dynamic>> endpoints, ThemeData theme) {
    if (endpoints.isEmpty) return const Center(child: Text('No endpoints found'));
    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: endpoints.length,
      itemBuilder: (ctx, i) {
        final ep = endpoints[i];
        final method = ep['method']?.toString() ?? '';
        final host = ep['host']?.toString() ?? '';
        final path = ep['path']?.toString() ?? '';
        final count = ep['count'] as int? ?? 0;
        return ListTile(
          dense: true,
          visualDensity: const VisualDensity(vertical: -3),
          title: Row(children: [
            Container(
              width: 48,
              padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
              decoration: BoxDecoration(
                color: Colors.grey.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(3),
              ),
              child: Text(method, textAlign: TextAlign.center,
                  style: const TextStyle(fontSize: 9, fontWeight: FontWeight.w700)),
            ),
            const SizedBox(width: 6),
            Expanded(
              child: Text('$host$path', maxLines: 1, overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontSize: 11, fontFamily: 'monospace')),
            ),
          ]),
          trailing: Text('x$count', style: theme.textTheme.labelSmall?.copyWith(fontWeight: FontWeight.w600)),
        );
      },
    );
  }

  Future<void> _pickAndParse() async {
    final result = await FilePicker.platform.pickFiles(type: FileType.any, withData: true);
    if (result == null || result.files.isEmpty) return;
    final file = result.files.first;
    if (file.bytes == null) return;
    setState(() => _captureLoading = true);
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.parseNetworkCapture(file.bytes!, file.name);
      setState(() { _captureLoading = false; _captureResult = res; });
    } catch (e) {
      setState(() => _captureLoading = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Parse error: $e')));
      }
    }
  }

  // ── Frida Scripts ──────────────────────────────────────────────────────────

  Widget _buildFrida(ThemeData theme) {
    Widget unpackCard() {
      return Padding(
        padding: const EdgeInsets.fromLTRB(12, 8, 12, 4),
        child: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: theme.colorScheme.tertiary.withValues(alpha: 0.08),
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: theme.colorScheme.tertiary.withValues(alpha: 0.3)),
          ),
          child: Row(children: [
            Icon(Icons.lock_open, size: 16, color: theme.colorScheme.tertiary),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                'Unpack (DEX dump): hooks libart at runtime and writes in-memory DEX to the app files dir. Set serial + target below, then exercise the app.',
                style: theme.textTheme.bodySmall?.copyWith(fontSize: 11),
              ),
            ),
            const SizedBox(width: 8),
            FilledButton.tonalIcon(
              onPressed: (_dumping || _fridaRunning) ? null : _runDexDump,
              icon: _dumping
                  ? const SizedBox(width: 12, height: 12, child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.lock_open, size: 14),
              label: const Text('Unpack', style: TextStyle(fontSize: 12)),
              style: FilledButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                visualDensity: VisualDensity.compact,
              ),
            ),
          ]),
        ),
      );
    }

    if (_scriptsLoading && _scripts == null) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          unpackCard(),
          const Divider(height: 1),
          _buildDumpRunPanel(theme),
          const Expanded(child: Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
            CircularProgressIndicator(), SizedBox(height: 12), Text('Loading Frida scripts...'),
          ]))),
        ],
      );
    }
    if (_scripts == null || _scripts!.isEmpty) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          unpackCard(),
          const Divider(height: 1),
          _buildDumpRunPanel(theme),
          Expanded(child: Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(Icons.code_off, size: 48, color: Colors.grey[400]),
            const SizedBox(height: 12),
            Text('No Frida scripts available', style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
            const SizedBox(height: 8),
            FilledButton.tonalIcon(
              onPressed: _scriptsLoading ? null : _loadScripts,
              icon: const Icon(Icons.refresh, size: 14),
              label: const Text('Reload'),
            ),
          ]))),
        ],
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        unpackCard(),
        if (_categories != null && _categories!.isNotEmpty)
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 4),
            child: Wrap(spacing: 6, runSpacing: 6, children: [
              FilterChip(
                label: const Text('All', style: TextStyle(fontSize: 11)),
                selected: _selectedCategory == null,
                onSelected: (_) => setState(() => _selectedCategory = null),
                visualDensity: VisualDensity.compact,
                materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              ..._categories!.map((cat) => FilterChip(
                label: Text(cat, style: const TextStyle(fontSize: 11)),
                selected: _selectedCategory == cat,
                onSelected: (_) => setState(() => _selectedCategory = _selectedCategory == cat ? null : cat),
                visualDensity: VisualDensity.compact,
                materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
              )),
            ]),
          ),
        const Divider(height: 1),
        Expanded(child: _buildScriptsList(theme)),
        if (_selectedScript != null) ...[
          const Divider(height: 1),
          _buildRunPanel(theme),
        ],
      ],
    );
  }

  Widget _buildScriptsList(ThemeData theme) {
    final filtered = _selectedCategory == null
        ? _scripts!
        : _scripts!.where((s) => s['category'] == _selectedCategory).toList();
    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: filtered.length,
      itemBuilder: (ctx, i) {
        final script = filtered[i];
        final name = script['name']?.toString() ?? 'Script ${i + 1}';
        final desc = script['description']?.toString() ?? '';
        final category = script['category']?.toString() ?? '';
        final id = script['id']?.toString() ?? '';
        final isSelected = _selectedScript == id;

        return Padding(
          padding: const EdgeInsets.only(bottom: 4),
          child: Container(
            decoration: BoxDecoration(
              color: isSelected
                  ? theme.colorScheme.primary.withValues(alpha: 0.08)
                  : theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
              borderRadius: BorderRadius.circular(6),
              border: isSelected ? Border.all(color: theme.colorScheme.primary.withValues(alpha: 0.4)) : null,
            ),
            child: ListTile(
              dense: true,
              visualDensity: const VisualDensity(vertical: -2),
              title: Text(name, style: theme.textTheme.bodySmall?.copyWith(fontWeight: FontWeight.w600)),
              subtitle: desc.isNotEmpty
                  ? Text(desc, maxLines: 2, overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.bodySmall?.copyWith(fontSize: 11, color: Colors.grey))
                  : null,
              trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                if (category.isNotEmpty)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                    decoration: BoxDecoration(
                      color: theme.colorScheme.primary.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Text(category, style: const TextStyle(fontSize: 9)),
                  ),
                const SizedBox(width: 4),
                IconButton(
                  icon: const Icon(Icons.copy, size: 14),
                  tooltip: 'Copy script',
                  visualDensity: VisualDensity.compact,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                  onPressed: () => _copyScript(id, name),
                ),
              ]),
              onTap: () => setState(() => _selectedScript = isSelected ? null : id),
            ),
          ),
        );
      },
    );
  }

  Widget _buildDumpRunPanel(ThemeData theme) {
    return Container(
      padding: const EdgeInsets.all(10),
      color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.2),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Expanded(child: TextField(
            controller: _serialController,
            decoration: const InputDecoration(
              labelText: 'Device serial', hintText: 'emulator-5554', isDense: true,
              contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 8),
              border: OutlineInputBorder(),
            ),
            style: const TextStyle(fontSize: 12),
          )),
          const SizedBox(width: 8),
          Expanded(child: TextField(
            controller: _targetController,
            decoration: const InputDecoration(
              labelText: 'Target package', hintText: 'com.example.app', isDense: true,
              contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 8),
              border: OutlineInputBorder(),
            ),
            style: const TextStyle(fontSize: 12),
          )),
        ]),
        if (_fridaRunOutput != null) ...[
          const SizedBox(height: 8),
          Container(
            constraints: const BoxConstraints(maxHeight: 150),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              borderRadius: BorderRadius.circular(4),
              border: Border.all(
                color: _fridaRunOutput!.startsWith('Error')
                    ? theme.colorScheme.error.withValues(alpha: 0.5)
                    : theme.colorScheme.primary.withValues(alpha: 0.3),
              ),
            ),
            child: Stack(children: [
              SingleChildScrollView(
                padding: const EdgeInsets.all(8),
                child: SelectableText(_fridaRunOutput!,
                  style: TextStyle(fontSize: 11, fontFamily: 'monospace',
                    color: _fridaRunOutput!.startsWith('Error') ? theme.colorScheme.error : null)),
              ),
              Positioned(top: 2, right: 2, child: IconButton(
                icon: const Icon(Icons.copy, size: 12),
                tooltip: 'Copy output',
                visualDensity: VisualDensity.compact,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 24, minHeight: 24),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: _fridaRunOutput!));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Output copied'), duration: Duration(seconds: 1)));
                },
              )),
            ]),
          ),
        ],
      ]),
    );
  }

  Widget _buildRunPanel(ThemeData theme) {
    return Container(
      padding: const EdgeInsets.all(10),
      color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.2),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Icon(Icons.play_arrow, size: 14, color: theme.colorScheme.primary),
          const SizedBox(width: 4),
          Text('Run on Device', style: theme.textTheme.labelMedium?.copyWith(fontWeight: FontWeight.w600)),
        ]),
        const SizedBox(height: 8),
        Row(children: [
          Expanded(child: TextField(
            controller: _serialController,
            decoration: const InputDecoration(
              labelText: 'Device serial', hintText: 'emulator-5554', isDense: true,
              contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 8),
              border: OutlineInputBorder(),
            ),
            style: const TextStyle(fontSize: 12),
          )),
          const SizedBox(width: 8),
          Expanded(child: TextField(
            controller: _targetController,
            decoration: const InputDecoration(
              labelText: 'Target package', hintText: 'com.example.app', isDense: true,
              contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 8),
              border: OutlineInputBorder(),
            ),
            style: const TextStyle(fontSize: 12),
          )),
          const SizedBox(width: 8),
          FilledButton.icon(
            onPressed: _fridaRunning ? null : () => _runScript(_selectedScript!),
            icon: _fridaRunning
                ? const SizedBox(width: 12, height: 12, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.play_arrow, size: 14),
            label: const Text('Run', style: TextStyle(fontSize: 12)),
            style: FilledButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              visualDensity: VisualDensity.compact,
            ),
          ),
        ]),
        if (_fridaRunOutput != null) ...[
          const SizedBox(height: 8),
          Container(
            constraints: const BoxConstraints(maxHeight: 150),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              borderRadius: BorderRadius.circular(4),
              border: Border.all(
                color: _fridaRunOutput!.startsWith('Error')
                    ? theme.colorScheme.error.withValues(alpha: 0.5)
                    : theme.colorScheme.primary.withValues(alpha: 0.3),
              ),
            ),
            child: Stack(children: [
              SingleChildScrollView(
                padding: const EdgeInsets.all(8),
                child: SelectableText(_fridaRunOutput!,
                  style: TextStyle(fontSize: 11, fontFamily: 'monospace',
                    color: _fridaRunOutput!.startsWith('Error') ? theme.colorScheme.error : null)),
              ),
              Positioned(top: 2, right: 2, child: IconButton(
                icon: const Icon(Icons.copy, size: 12),
                tooltip: 'Copy output',
                visualDensity: VisualDensity.compact,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 24, minHeight: 24),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: _fridaRunOutput!));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Output copied'), duration: Duration(seconds: 1)));
                },
              )),
            ]),
          ),
        ],
      ]),
    );
  }

  Future<void> _copyScript(String id, String name) async {
    try {
      final api = ref.read(apiServiceProvider);
      final full = await api.getFridaScript(id);
      final code = full['code']?.toString() ?? '';
      if (code.isNotEmpty) {
        Clipboard.setData(ClipboardData(text: code));
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('$name copied'), duration: const Duration(seconds: 1)));
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error: $e')));
      }
    }
  }

  Future<void> _runScript(String scriptId) async {
    final serial = _serialController.text.trim();
    final target = _targetController.text.trim();
    if (serial.isEmpty || target.isEmpty) {
      setState(() => _fridaRunOutput = 'Error: device serial and target package are required');
      return;
    }
    setState(() { _fridaRunning = true; _fridaRunOutput = 'Running script...'; });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.runFridaScript(scriptId, serial, target);
      final output = res['output']?.toString() ?? '';
      final error = res['error']?.toString();
      setState(() {
        _fridaRunning = false;
        _fridaRunOutput = error != null ? 'Error: $error\n$output' : output.isEmpty ? '(no output)' : output;
      });
    } catch (e) {
      setState(() { _fridaRunning = false; _fridaRunOutput = 'Error: $e'; });
    }
  }

  Future<void> _runDexDump() async {
    final serial = _serialController.text.trim();
    final target = _targetController.text.trim();
    if (serial.isEmpty || target.isEmpty) {
      setState(() => _fridaRunOutput = 'Error: device serial and target package are required');
      return;
    }
    setState(() { _dumping = true; _fridaRunOutput = 'Spawning $target and dumping in-memory DEX (give the app a moment to unpack)...'; });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.runFridaCode(serial, target, _dexDumpScript, timeout: 60);
      final output = res['output']?.toString() ?? '';
      final error = res['error']?.toString();
      setState(() {
        _dumping = false;
        _fridaRunOutput = error != null ? 'Error: $error\n$output' : output.isEmpty ? '(no output)' : output;
      });
    } catch (e) {
      setState(() { _dumping = false; _fridaRunOutput = 'Error: $e'; });
    }
  }

  Future<void> _loadScripts() async {
    setState(() => _scriptsLoading = true);
    try {
      final api = ref.read(apiServiceProvider);
      final scripts = await api.listFridaScripts();
      final categories = await api.listFridaCategories();
      setState(() { _scripts = scripts; _categories = categories; _scriptsLoading = false; });
    } catch (e) {
      setState(() { _scriptsLoading = false; _scripts = []; });
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  Color _methodColor(String method) {
    switch (method) {
      case 'POST': return Colors.orange;
      case 'PUT': case 'PATCH': return Colors.blue;
      case 'DELETE': return Colors.red;
      default: return Colors.green;
    }
  }

  Color _categoryColor(String category) {
    switch (category) {
      case 'analytics': return Colors.purple;
      case 'ad': return Colors.red;
      case 'cloud': return Colors.blue;
      case 'cdn': return Colors.teal;
      case 'social': return Colors.indigo;
      case 'payment': return Colors.amber.shade800;
      default: return Colors.grey;
    }
  }
}
