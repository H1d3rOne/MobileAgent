import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/services/api_service.dart';

final visibleSkillsProvider = FutureProvider<List<Map<String, dynamic>>>((ref) async {
  return ref.watch(apiServiceProvider).listSkills();
});

final installedSkillsProvider = FutureProvider<List<Map<String, dynamic>>>((ref) async {
  return ref.watch(apiServiceProvider).listInstalledSkills();
});

final skillCatalogProvider = FutureProvider<List<Map<String, dynamic>>>((ref) async {
  return ref.watch(apiServiceProvider).listSkillCatalog();
});

class SkillsPage extends ConsumerStatefulWidget {
  const SkillsPage({super.key});

  @override
  ConsumerState<SkillsPage> createState() => _SkillsPageState();
}

class _SkillsPageState extends ConsumerState<SkillsPage> {
  final _idController = TextEditingController();
  final _nameController = TextEditingController();
  final _descriptionController = TextEditingController();
  final _builtinIdController = TextEditingController();
  bool _manualEnabled = true;
  bool _submitting = false;

  @override
  void dispose() {
    _idController.dispose();
    _nameController.dispose();
    _descriptionController.dispose();
    _builtinIdController.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    ref.invalidate(visibleSkillsProvider);
    ref.invalidate(installedSkillsProvider);
    ref.invalidate(skillCatalogProvider);
    await Future.wait([
      ref.read(visibleSkillsProvider.future),
      ref.read(installedSkillsProvider.future),
      ref.read(skillCatalogProvider.future),
    ]);
  }

  Future<void> _handleManualInstall() async {
    if (_idController.text.trim().isEmpty || _builtinIdController.text.trim().isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Skill ID and builtin skill ID are required')),
      );
      return;
    }
    setState(() => _submitting = true);
    try {
      await ref.read(apiServiceProvider).installSkill({
        'id': _idController.text.trim(),
        'name': _nameController.text.trim(),
        'description': _descriptionController.text.trim(),
        'builtin_skill_id': _builtinIdController.text.trim(),
        'source': 'manual',
        'enabled': _manualEnabled,
      });
      _idController.clear();
      _nameController.clear();
      _descriptionController.clear();
      _builtinIdController.clear();
      await _refresh();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Skill installed')),
      );
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Install failed: $error')),
      );
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  Future<void> _toggleSkill(String id, bool enabled) async {
    try {
      if (enabled) {
        await ref.read(apiServiceProvider).enableSkill(id);
      } else {
        await ref.read(apiServiceProvider).disableSkill(id);
      }
      await _refresh();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Update failed: $error')),
      );
    }
  }

  Future<void> _installCatalogSkill(Map<String, dynamic> item) async {
    try {
      await ref.read(apiServiceProvider).installSkill({
        'id': item['id'],
        'name': item['name'],
        'description': item['description'],
        'version': item['version'],
        'builtin_skill_id': item['builtin_skill_id'] ?? item['id'],
        'source': item['source'] ?? 'builtin',
        'source_id': item['source_id'] ?? '',
        'enabled': true,
      });
      await _refresh();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Install failed: $error')),
      );
    }
  }

  Future<void> _deleteSkill(String id) async {
    try {
      await ref.read(apiServiceProvider).deleteSkill(id);
      await _refresh();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Delete failed: $error')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final visibleSkills = ref.watch(visibleSkillsProvider);
    final installedSkills = ref.watch(installedSkillsProvider);
    final catalog = ref.watch(skillCatalogProvider);

    return RefreshIndicator(
      onRefresh: _refresh,
      child: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          Row(
            children: [
              Expanded(child: Text('Skills', style: theme.textTheme.headlineMedium)),
              FilledButton.icon(
                onPressed: _refresh,
                icon: const Icon(Icons.refresh),
                label: const Text('Refresh'),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Manage installed skills, browse the catalog, and register manual metadata bindings to builtin implementations.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 24),
          _buildSectionTitle(context, 'Installed / Active'),
          const SizedBox(height: 12),
          installedSkills.when(
            data: (items) => items.isEmpty
                ? const Card(child: Padding(padding: EdgeInsets.all(16), child: Text('No installed skills yet')))
                : Column(
                    children: items.map((item) => _installedSkillCard(theme, item)).toList(),
                  ),
            loading: () => const Center(child: Padding(padding: EdgeInsets.all(16), child: CircularProgressIndicator())),
            error: (error, _) => Card(child: Padding(padding: const EdgeInsets.all(16), child: Text('Error: $error'))),
          ),
          const SizedBox(height: 24),
          _buildSectionTitle(context, 'Visible Runtime Skills'),
          const SizedBox(height: 12),
          visibleSkills.when(
            data: (items) => items.isEmpty
                ? const Card(child: Padding(padding: EdgeInsets.all(16), child: Text('No runtime skills available')))
                : Column(
                    children: items.map((item) => _runtimeSkillCard(theme, item)).toList(),
                  ),
            loading: () => const Center(child: Padding(padding: EdgeInsets.all(16), child: CircularProgressIndicator())),
            error: (error, _) => Card(child: Padding(padding: const EdgeInsets.all(16), child: Text('Error: $error'))),
          ),
          const SizedBox(height: 24),
          _buildSectionTitle(context, 'Catalog'),
          const SizedBox(height: 12),
          catalog.when(
            data: (items) => items.isEmpty
                ? const Card(child: Padding(padding: EdgeInsets.all(16), child: Text('No catalog entries available')))
                : Column(
                    children: items.map((item) => _catalogSkillCard(theme, item)).toList(),
                  ),
            loading: () => const Center(child: Padding(padding: EdgeInsets.all(16), child: CircularProgressIndicator())),
            error: (error, _) => Card(child: Padding(padding: const EdgeInsets.all(16), child: Text('Error: $error'))),
          ),
          const SizedBox(height: 24),
          _buildSectionTitle(context, 'Manual Install'),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  TextField(
                    controller: _idController,
                    decoration: const InputDecoration(labelText: 'Skill ID'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _nameController,
                    decoration: const InputDecoration(labelText: 'Display Name'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _builtinIdController,
                    decoration: const InputDecoration(labelText: 'Builtin Skill ID'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _descriptionController,
                    minLines: 2,
                    maxLines: 4,
                    decoration: const InputDecoration(labelText: 'Description'),
                  ),
                  const SizedBox(height: 12),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Enable after install'),
                    value: _manualEnabled,
                    onChanged: (value) => setState(() => _manualEnabled = value),
                  ),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    onPressed: _submitting ? null : _handleManualInstall,
                    icon: _submitting
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.add),
                    label: const Text('Install Skill Metadata'),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionTitle(BuildContext context, String title) {
    return Text(title, style: Theme.of(context).textTheme.titleLarge);
  }

  Widget _installedSkillCard(ThemeData theme, Map<String, dynamic> item) {
    final enabled = item['enabled'] == true;
    final available = item['available'] != false;
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
                  onChanged: available ? (value) => _toggleSkill((item['id'] ?? '').toString(), value) : null,
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
                Chip(label: Text(available ? 'available' : 'unavailable implementation')),
              ],
            ),
            const SizedBox(height: 12),
            TextButton.icon(
              onPressed: () => _deleteSkill((item['id'] ?? '').toString()),
              icon: const Icon(Icons.delete_outline),
              label: const Text('Remove'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _runtimeSkillCard(ThemeData theme, Map<String, dynamic> item) {
    final parameters = item['parameters'];
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.extension, color: theme.colorScheme.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: SelectableText(
                    (item['name'] ?? '').toString(),
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontFamily: 'monospace',
                      fontWeight: FontWeight.w600,
                    ),
                  ),
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
                Chip(label: Text((item['source'] ?? 'builtin').toString())),
                Chip(label: Text(item['enabled'] == true ? 'enabled' : 'disabled')),
              ],
            ),
            const SizedBox(height: 12),
            Text('Parameters', style: theme.textTheme.labelLarge),
            const SizedBox(height: 6),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                parameters == null ? '{}' : parameters.toString(),
                style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _catalogSkillCard(ThemeData theme, Map<String, dynamic> item) {
    final installed = item['installed'] == true;
    final available = item['available'] != false;
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
                    onPressed: () => _installCatalogSkill(item),
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
                Chip(label: Text(available ? 'implementation available' : 'metadata only')),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
