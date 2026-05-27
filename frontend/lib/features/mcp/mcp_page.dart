import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/services/api_service.dart';

final mcpInstalledProvider = FutureProvider<List<Map<String, dynamic>>>((ref) async {
  return ref.watch(apiServiceProvider).listInstalledMcp();
});

final mcpCatalogProvider = FutureProvider<List<Map<String, dynamic>>>((ref) async {
  return ref.watch(apiServiceProvider).listMcpCatalog();
});

final marketSourcesProvider = FutureProvider<List<Map<String, dynamic>>>((ref) async {
  return ref.watch(apiServiceProvider).listMarketSources();
});

class McpPage extends ConsumerStatefulWidget {
  const McpPage({super.key});

  @override
  ConsumerState<McpPage> createState() => _McpPageState();
}

class _McpPageState extends ConsumerState<McpPage> {
  final _idController = TextEditingController();
  final _nameController = TextEditingController();
  final _descriptionController = TextEditingController();
  final _commandController = TextEditingController();
  final _envController = TextEditingController();
  final _cwdController = TextEditingController();
  final _sourceUrlController = TextEditingController();
  final _sourceNameController = TextEditingController();
  bool _enableAfterInstall = true;
  bool _busy = false;

  @override
  void dispose() {
    _idController.dispose();
    _nameController.dispose();
    _descriptionController.dispose();
    _commandController.dispose();
    _envController.dispose();
    _cwdController.dispose();
    _sourceUrlController.dispose();
    _sourceNameController.dispose();
    super.dispose();
  }

  Future<void> _refreshAll() async {
    ref.invalidate(mcpInstalledProvider);
    ref.invalidate(mcpCatalogProvider);
    ref.invalidate(marketSourcesProvider);
    await Future.wait([
      ref.read(mcpInstalledProvider.future),
      ref.read(mcpCatalogProvider.future),
      ref.read(marketSourcesProvider.future),
    ]);
  }

  Map<String, String> _parseEnv(String raw) {
    final env = <String, String>{};
    for (final line in raw.split('\n')) {
      final trimmed = line.trim();
      if (trimmed.isEmpty) continue;
      final idx = trimmed.indexOf('=');
      if (idx <= 0) continue;
      env[trimmed.substring(0, idx).trim()] = trimmed.substring(idx + 1).trim();
    }
    return env;
  }

  List<String> _parseCommand(String raw) {
    return raw
        .split(' ')
        .map((part) => part.trim())
        .where((part) => part.isNotEmpty)
        .toList();
  }

  Future<void> _installManualMcp() async {
    if (_idController.text.trim().isEmpty || _commandController.text.trim().isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('MCP ID and command are required')),
      );
      return;
    }
    setState(() => _busy = true);
    try {
      await ref.read(apiServiceProvider).installMcp({
        'id': _idController.text.trim(),
        'name': _nameController.text.trim(),
        'description': _descriptionController.text.trim(),
        'command': _parseCommand(_commandController.text.trim()),
        'env': _parseEnv(_envController.text),
        'cwd': _cwdController.text.trim(),
        'source': 'manual',
        'enabled': _enableAfterInstall,
      }, manual: true);
      _idController.clear();
      _nameController.clear();
      _descriptionController.clear();
      _commandController.clear();
      _envController.clear();
      _cwdController.clear();
      await _refreshAll();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('MCP installed')),
      );
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Install failed: $error')),
      );
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _installCatalogMcp(Map<String, dynamic> item) async {
    try {
      await ref.read(apiServiceProvider).installMcp({
        'id': item['id'],
        'name': item['name'],
        'description': item['description'],
        'version': item['version'],
        'command': (item['command'] as List?) ?? const [],
        'env': item['env'] ?? const {},
        'cwd': item['cwd'] ?? '',
        'source': item['source'] ?? 'builtin',
        'source_id': item['source_id'] ?? '',
        'enabled': true,
      });
      await _refreshAll();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Install failed: $error')),
      );
    }
  }

  Future<void> _toggleMcp(String id, bool enabled) async {
    try {
      if (enabled) {
        await ref.read(apiServiceProvider).enableMcp(id);
      } else {
        await ref.read(apiServiceProvider).disableMcp(id);
      }
      await _refreshAll();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Update failed: $error')),
      );
    }
  }

  Future<void> _restartMcp(String id) async {
    try {
      await ref.read(apiServiceProvider).restartMcp(id);
      await _refreshAll();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Restart failed: $error')),
      );
    }
  }

  Future<void> _deleteMcp(String id) async {
    try {
      await ref.read(apiServiceProvider).deleteMcp(id);
      await _refreshAll();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Delete failed: $error')),
      );
    }
  }

  Future<void> _addSource() async {
    if (_sourceUrlController.text.trim().isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Market source URL is required')),
      );
      return;
    }
    try {
      await ref.read(apiServiceProvider).addMarketSource(
            url: _sourceUrlController.text.trim(),
            name: _sourceNameController.text.trim(),
          );
      _sourceUrlController.clear();
      _sourceNameController.clear();
      await _refreshAll();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Add source failed: $error')),
      );
    }
  }

  Future<void> _deleteSource(String id) async {
    try {
      await ref.read(apiServiceProvider).deleteMarketSource(id);
      await _refreshAll();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Delete source failed: $error')),
      );
    }
  }

  Future<void> _refreshMarket() async {
    try {
      await ref.read(apiServiceProvider).refreshMarket();
      await _refreshAll();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Refresh failed: $error')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final installed = ref.watch(mcpInstalledProvider);
    final catalog = ref.watch(mcpCatalogProvider);
    final sources = ref.watch(marketSourcesProvider);

    return RefreshIndicator(
      onRefresh: _refreshAll,
      child: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          Row(
            children: [
              Expanded(child: Text('MCP Servers', style: theme.textTheme.headlineMedium)),
              FilledButton.icon(
                onPressed: _refreshMarket,
                icon: const Icon(Icons.sync),
                label: const Text('Refresh Market'),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Install, enable, disable, restart, and remove MCP servers from built-in, remote, or manual sources.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 24),
          Text('Installed / Running', style: theme.textTheme.titleLarge),
          const SizedBox(height: 12),
          installed.when(
            data: (items) => items.isEmpty
                ? const Card(child: Padding(padding: EdgeInsets.all(16), child: Text('No MCP servers installed')))
                : Column(children: items.map((item) => _installedCard(theme, item)).toList()),
            loading: () => const Center(child: Padding(padding: EdgeInsets.all(16), child: CircularProgressIndicator())),
            error: (error, _) => Card(child: Padding(padding: const EdgeInsets.all(16), child: Text('Error: $error'))),
          ),
          const SizedBox(height: 24),
          Text('Catalog', style: theme.textTheme.titleLarge),
          const SizedBox(height: 12),
          catalog.when(
            data: (items) => items.isEmpty
                ? const Card(child: Padding(padding: EdgeInsets.all(16), child: Text('No market catalog entries')))
                : Column(children: items.map((item) => _catalogCard(theme, item)).toList()),
            loading: () => const Center(child: Padding(padding: EdgeInsets.all(16), child: CircularProgressIndicator())),
            error: (error, _) => Card(child: Padding(padding: const EdgeInsets.all(16), child: Text('Error: $error'))),
          ),
          const SizedBox(height: 24),
          Text('Market Sources', style: theme.textTheme.titleLarge),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                children: [
                  TextField(
                    controller: _sourceNameController,
                    decoration: const InputDecoration(labelText: 'Source Name'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _sourceUrlController,
                    decoration: const InputDecoration(labelText: 'Catalog URL'),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      FilledButton.icon(
                        onPressed: _addSource,
                        icon: const Icon(Icons.add_link),
                        label: const Text('Add Source'),
                      ),
                      const SizedBox(width: 12),
                      OutlinedButton.icon(
                        onPressed: _refreshMarket,
                        icon: const Icon(Icons.refresh),
                        label: const Text('Refresh'),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          sources.when(
            data: (items) => items.isEmpty
                ? const Card(child: Padding(padding: EdgeInsets.all(16), child: Text('No market sources')))
                : Column(children: items.map((item) => _sourceCard(theme, item)).toList()),
            loading: () => const Center(child: Padding(padding: EdgeInsets.all(16), child: CircularProgressIndicator())),
            error: (error, _) => Card(child: Padding(padding: const EdgeInsets.all(16), child: Text('Error: $error'))),
          ),
          const SizedBox(height: 24),
          Text('Manual Install', style: theme.textTheme.titleLarge),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                children: [
                  TextField(
                    controller: _idController,
                    decoration: const InputDecoration(labelText: 'MCP ID'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _nameController,
                    decoration: const InputDecoration(labelText: 'Display Name'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _descriptionController,
                    decoration: const InputDecoration(labelText: 'Description'),
                    minLines: 2,
                    maxLines: 4,
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _commandController,
                    decoration: const InputDecoration(labelText: 'Command'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _cwdController,
                    decoration: const InputDecoration(labelText: 'Working Directory'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _envController,
                    decoration: const InputDecoration(labelText: 'Env (KEY=value, one per line)'),
                    minLines: 2,
                    maxLines: 4,
                  ),
                  const SizedBox(height: 12),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Enable after install'),
                    value: _enableAfterInstall,
                    onChanged: (value) => setState(() => _enableAfterInstall = value),
                  ),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    onPressed: _busy ? null : _installManualMcp,
                    icon: _busy
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.add_box_outlined),
                    label: const Text('Install MCP'),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _installedCard(ThemeData theme, Map<String, dynamic> item) {
    final enabled = item['enabled'] == true;
    final alive = item['alive'] == true;
    final toolCount = item['tool_count'] ?? 0;
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(child: Text((item['name'] ?? item['id']).toString(), style: theme.textTheme.titleMedium)),
                Switch(
                  value: enabled,
                  onChanged: (value) => _toggleMcp((item['id'] ?? '').toString(), value),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text((item['description'] ?? 'No description').toString()),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                Chip(label: Text((item['source'] ?? 'manual').toString())),
                Chip(label: Text(enabled ? 'enabled' : 'disabled')),
                Chip(label: Text(alive ? 'alive' : 'offline')),
                Chip(label: Text('tools: $toolCount')),
              ],
            ),
            if ((item['command'] as List?) != null) ...[
              const SizedBox(height: 12),
              SelectableText(
                (item['command'] as List).join(' '),
                style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
              ),
            ],
            if ((item['last_error'] ?? '').toString().isNotEmpty) ...[
              const SizedBox(height: 12),
              Text(
                (item['last_error'] ?? '').toString(),
                style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
              ),
            ],
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              children: [
                OutlinedButton.icon(
                  onPressed: () => _restartMcp((item['id'] ?? '').toString()),
                  icon: const Icon(Icons.restart_alt),
                  label: const Text('Restart'),
                ),
                TextButton.icon(
                  onPressed: () => _deleteMcp((item['id'] ?? '').toString()),
                  icon: const Icon(Icons.delete_outline),
                  label: const Text('Remove'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _catalogCard(ThemeData theme, Map<String, dynamic> item) {
    final installed = item['installed'] == true;
    final command = item['command'] is List ? (item['command'] as List).join(' ') : '';
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(child: Text((item['name'] ?? item['id']).toString(), style: theme.textTheme.titleMedium)),
                if (!installed)
                  FilledButton(
                    onPressed: () => _installCatalogMcp(item),
                    child: const Text('Install'),
                  )
                else
                  const Chip(label: Text('Installed')),
              ],
            ),
            const SizedBox(height: 8),
            Text((item['description'] ?? 'No description').toString()),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                Chip(label: Text((item['source'] ?? 'builtin').toString())),
                if ((item['version'] ?? '').toString().isNotEmpty)
                  Chip(label: Text((item['version'] ?? '').toString())),
              ],
            ),
            if (command.isNotEmpty) ...[
              const SizedBox(height: 12),
              SelectableText(command, style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace')),
            ],
          ],
        ),
      ),
    );
  }

  Widget _sourceCard(ThemeData theme, Map<String, dynamic> item) {
    final builtin = item['builtin'] == true;
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(child: Text((item['name'] ?? item['id']).toString(), style: theme.textTheme.titleMedium)),
                Chip(label: Text((item['type'] ?? 'remote').toString())),
              ],
            ),
            const SizedBox(height: 8),
            if ((item['url'] ?? '').toString().isNotEmpty)
              SelectableText((item['url'] ?? '').toString()),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                Chip(label: Text(item['enabled'] == true ? 'enabled' : 'disabled')),
                if ((item['last_error'] ?? '').toString().isNotEmpty)
                  const Chip(label: Text('error')),
              ],
            ),
            if ((item['last_error'] ?? '').toString().isNotEmpty) ...[
              const SizedBox(height: 12),
              Text(
                (item['last_error'] ?? '').toString(),
                style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
              ),
            ],
            if (!builtin) ...[
              const SizedBox(height: 12),
              TextButton.icon(
                onPressed: () => _deleteSource((item['id'] ?? '').toString()),
                icon: const Icon(Icons.delete_outline),
                label: const Text('Remove Source'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
