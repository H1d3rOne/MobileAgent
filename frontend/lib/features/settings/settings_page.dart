import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../core/services/api_service.dart';
import '../../core/theme/app_theme.dart';

class SettingsPage extends ConsumerStatefulWidget {
  const SettingsPage({super.key});
  @override
  ConsumerState<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends ConsumerState<SettingsPage> {
  late TextEditingController _adbPathController;
  late String _approvalMode;

  final _nameCtrl = TextEditingController();
  final _urlCtrl = TextEditingController();
  final _keyCtrl = TextEditingController();
  final _modelCtrl = TextEditingController();
  String _apiType = 'chat_completions';
  bool _obscureKey = true;
  List<String> _modelList = [];
  bool _loadingModels = false;

  @override
  void initState() {
    super.initState();
    final config = ref.read(apiConfigProvider);
    _adbPathController = TextEditingController(text: config.adbPath);
    _approvalMode = config.approvalMode.isNotEmpty ? config.approvalMode : 'approval';
    _syncProviderFields(config.activeProvider);
  }

  void _syncProviderFields(LLMProvider? provider) {
    _nameCtrl.text = provider?.name ?? '';
    _urlCtrl.text = provider?.baseUrl ?? '';
    _keyCtrl.text = provider?.apiKey ?? '';
    _modelCtrl.text = provider?.model ?? '';
    _apiType = provider?.apiType ?? 'chat_completions';
    _modelList = [];
  }

  @override
  void dispose() {
    _adbPathController.dispose();
    _nameCtrl.dispose();
    _urlCtrl.dispose();
    _keyCtrl.dispose();
    _modelCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final config = ref.watch(apiConfigProvider);
    final providers = config.providers;
    final activeProvider = config.activeProvider;

    return Scaffold(
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          Text('Settings', style: theme.textTheme.headlineMedium),
          const SizedBox(height: 24),

          _buildSectionHeader('LLM Provider', Icons.smart_toy, theme),
          const SizedBox(height: 4),
          Text('Select a provider or add a new one',
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant)),
          const SizedBox(height: 12),

          Row(
            children: [
              Expanded(
                child: DropdownButtonFormField<String>(
                  value: activeProvider?.id,
                  decoration: const InputDecoration(
                    labelText: 'Provider',
                    prefixIcon: Icon(Icons.cloud),
                  ),
                  items: providers.map((p) => DropdownMenuItem(
                    value: p.id,
                    child: Text(p.name.isNotEmpty ? p.name : p.model.isNotEmpty ? p.model : 'Unnamed'),
                  )).toList(),
                  onChanged: (id) {
                    if (id != null) {
                      ref.read(apiConfigProvider.notifier).setActiveProvider(id);
                      final selected = providers.firstWhere((p) => p.id == id);
                      setState(() => _syncProviderFields(selected));
                    }
                  },
                ),
              ),
              const SizedBox(width: 8),
              IconButton.filled(
                onPressed: _addProvider,
                icon: const Icon(Icons.add),
                tooltip: 'Add Provider',
              ),
              if (providers.length > 1 && activeProvider != null)
                IconButton(
                  onPressed: () => _deleteProvider(activeProvider),
                  icon: const Icon(Icons.delete_outline),
                  tooltip: 'Delete Provider',
                ),
            ],
          ),

          if (activeProvider != null) ...[
            const SizedBox(height: 16),
            TextField(
              controller: _nameCtrl,
              decoration: const InputDecoration(
                labelText: 'Name',
                hintText: 'e.g. OpenAI, Claude, DeepSeek',
                prefixIcon: Icon(Icons.label),
              ),
              onChanged: (_) => _saveProviderFields(),
            ),
            const SizedBox(height: 12),
            DropdownButtonFormField<String>(
              value: _apiType,
              decoration: const InputDecoration(
                labelText: 'API Type',
                prefixIcon: Icon(Icons.api),
              ),
              items: const [
                DropdownMenuItem(value: 'chat_completions', child: Text('Chat Completions')),
                DropdownMenuItem(value: 'responses', child: Text('Responses')),
              ],
              onChanged: (v) {
                if (v != null) {
                  setState(() => _apiType = v);
                  _saveProviderFields();
                }
              },
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _urlCtrl,
              decoration: const InputDecoration(
                labelText: 'Base URL',
                hintText: 'https://api.openai.com/v1',
                prefixIcon: Icon(Icons.link),
              ),
              onChanged: (_) => _saveProviderFields(),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _keyCtrl,
              obscureText: _obscureKey,
              decoration: InputDecoration(
                labelText: 'API Key',
                prefixIcon: const Icon(Icons.key),
                suffixIcon: IconButton(
                  icon: Icon(_obscureKey ? Icons.visibility_off : Icons.visibility),
                  onPressed: () => setState(() => _obscureKey = !_obscureKey),
                ),
              ),
              onChanged: (_) => _saveProviderFields(),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: DropdownButtonFormField<String>(
                    value: _modelList.contains(_modelCtrl.text) ? _modelCtrl.text : null,
                    decoration: InputDecoration(
                      labelText: 'Model',
                      hintText: _modelList.isEmpty ? 'Click refresh to load models' : 'Select a model',
                      prefixIcon: const Icon(Icons.psychology),
                    ),
                    items: [
                      if (_modelCtrl.text.isNotEmpty && !_modelList.contains(_modelCtrl.text))
                        DropdownMenuItem(value: _modelCtrl.text, child: Text(_modelCtrl.text)),
                      ..._modelList.map((m) => DropdownMenuItem(value: m, child: Text(m))),
                    ],
                    onChanged: (v) {
                      if (v != null) {
                        setState(() => _modelCtrl.text = v);
                        _saveProviderFields();
                      }
                    },
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  onPressed: _loadingModels ? null : _fetchModels,
                  icon: _loadingModels
                      ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Icon(Icons.refresh),
                  tooltip: 'Fetch models from API',
                ),
              ],
            ),
          ],
          const SizedBox(height: 32),

          _buildSectionHeader('ADB Configuration', Icons.phone_android, theme),
          const SizedBox(height: 12),
          TextField(
            controller: _adbPathController,
            decoration: const InputDecoration(
              labelText: 'ADB Path',
              hintText: 'adb',
              prefixIcon: Icon(Icons.terminal),
            ),
            onChanged: (_) => _saveGlobalConfig(),
          ),
          const SizedBox(height: 32),

          _buildSectionHeader('Agent Behavior', Icons.security, theme),
          const SizedBox(height: 4),
          Text('Control what the agent can run when it calls dangerous tools.',
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant)),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            value: _approvalMode,
            decoration: const InputDecoration(
              labelText: 'Approval Mode',
              prefixIcon: Icon(Icons.shield),
            ),
            items: const [
              DropdownMenuItem(value: 'deny', child: Text('Deny — block all dangerous tools')),
              DropdownMenuItem(value: 'approval', child: Text('Approval — ask before running')),
              DropdownMenuItem(value: 'yolo', child: Text('Yolo — allow without prompting')),
            ],
            onChanged: (value) {
              if (value != null) {
                setState(() => _approvalMode = value);
                _saveGlobalConfig();
              }
            },
          ),
          const SizedBox(height: 32),

          _buildSectionHeader('Appearance', Icons.palette, theme),
          const SizedBox(height: 12),
          ListTile(
            leading: const Icon(Icons.dark_mode),
            title: const Text('Dark Mode'),
            trailing: Switch(
              value: theme.brightness == Brightness.dark,
              onChanged: (_) => ref.read(themeProvider.notifier).toggle(),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(String title, IconData icon, ThemeData theme) {
    return Row(
      children: [
        Icon(icon, color: theme.colorScheme.primary),
        const SizedBox(width: 8),
        Text(title, style: theme.textTheme.titleLarge),
      ],
    );
  }

  void _saveProviderFields() {
    final config = ref.read(apiConfigProvider);
    final active = config.activeProvider;
    if (active == null) return;
    ref.read(apiConfigProvider.notifier).updateProvider(active.copyWith(
      name: _nameCtrl.text.trim(),
      baseUrl: _urlCtrl.text.trim(),
      apiKey: _keyCtrl.text.trim(),
      model: _modelCtrl.text.trim(),
      apiType: _apiType,
    ));
  }

  void _saveGlobalConfig() {
    final config = ref.read(apiConfigProvider);
    ref.read(apiConfigProvider.notifier).update(config.copyWith(
      adbPath: _adbPathController.text.trim().isEmpty ? 'adb' : _adbPathController.text.trim(),
      approvalMode: _approvalMode,
    ));
  }

  void _addProvider() {
    final id = DateTime.now().millisecondsSinceEpoch.toString();
    final provider = LLMProvider(id: id, name: '', apiKey: '', baseUrl: '', model: '');
    ref.read(apiConfigProvider.notifier).addProvider(provider);
    setState(() => _syncProviderFields(provider));
  }

  Future<void> _fetchModels() async {
    final baseUrl = _urlCtrl.text.trim();
    final apiKey = _keyCtrl.text.trim();
    if (baseUrl.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter a Base URL first')),
      );
      return;
    }
    setState(() => _loadingModels = true);
    try {
      final dio = Dio();
      final headers = <String, dynamic>{};
      if (apiKey.isNotEmpty) {
        headers['Authorization'] = 'Bearer $apiKey';
      }
      final url = baseUrl.endsWith('/') ? '${baseUrl}models' : '$baseUrl/models';
      final resp = await dio.get(url, options: Options(headers: headers));
      final data = resp.data;
      final List models;
      if (data is Map && data['data'] is List) {
        models = data['data'];
      } else if (data is List) {
        models = data;
      } else {
        models = [];
      }
      final ids = models
          .map((m) => m is Map ? (m['id'] ?? m['name'] ?? '').toString() : m.toString())
          .where((s) => s.isNotEmpty)
          .toList()
        ..sort();
      setState(() {
        _modelList = ids;
        _loadingModels = false;
      });
    } catch (e) {
      setState(() => _loadingModels = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to fetch models: $e')),
        );
      }
    }
  }

  void _deleteProvider(LLMProvider provider) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete Provider'),
        content: Text('Remove "${provider.name.isNotEmpty ? provider.name : "this provider"}"?'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          TextButton(
            onPressed: () {
              ref.read(apiConfigProvider.notifier).removeProvider(provider.id);
              Navigator.pop(ctx);
              final config = ref.read(apiConfigProvider);
              setState(() => _syncProviderFields(config.activeProvider));
            },
            child: const Text('Delete', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
  }
}
