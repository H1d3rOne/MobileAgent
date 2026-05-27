import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/services/api_service.dart';

final memoryQueryProvider = StateProvider<String>((ref) => '');
final memoryScopeProvider = StateProvider<String>((ref) => '');
final memoryListProvider = FutureProvider<List<Map<String, dynamic>>>((ref) async {
  final api = ref.watch(apiServiceProvider);
  final query = ref.watch(memoryQueryProvider);
  final scope = ref.watch(memoryScopeProvider);
  return api.listMemory(query: query, scope: scope);
});

class MemoryPage extends ConsumerStatefulWidget {
  const MemoryPage({super.key});

  @override
  ConsumerState<MemoryPage> createState() => _MemoryPageState();
}

class _MemoryPageState extends ConsumerState<MemoryPage> {
  final _searchController = TextEditingController();
  final _keyController = TextEditingController();
  final _valueController = TextEditingController();
  final _scopeController = TextEditingController(text: 'global');
  final _tagsController = TextEditingController();
  bool _saving = false;

  @override
  void dispose() {
    _searchController.dispose();
    _keyController.dispose();
    _valueController.dispose();
    _scopeController.dispose();
    _tagsController.dispose();
    super.dispose();
  }

  Future<void> _createMemory() async {
    final key = _keyController.text.trim();
    final value = _valueController.text.trim();
    if (key.isEmpty || value.isEmpty || _saving) return;
    setState(() => _saving = true);
    try {
      await ref.read(apiServiceProvider).createMemory(
            key: key,
            value: value,
            scope: _scopeController.text.trim().isEmpty ? 'global' : _scopeController.text.trim(),
            tags: _tagsController.text.trim(),
          );
      _keyController.clear();
      _valueController.clear();
      _tagsController.clear();
      ref.invalidate(memoryListProvider);
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _deleteMemory(String id) async {
    await ref.read(apiServiceProvider).deleteMemory(id);
    ref.invalidate(memoryListProvider);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final memories = ref.watch(memoryListProvider);

    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Memory', style: theme.textTheme.headlineMedium),
          const SizedBox(height: 8),
          Text(
            'Inspect and manage agent memory entries stored by the backend.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _searchController,
                  decoration: const InputDecoration(
                    labelText: 'Search memory',
                    prefixIcon: Icon(Icons.search),
                  ),
                  onChanged: (value) {
                    ref.read(memoryQueryProvider.notifier).state = value.trim();
                  },
                ),
              ),
              const SizedBox(width: 12),
              SizedBox(
                width: 180,
                child: TextField(
                  decoration: const InputDecoration(
                    labelText: 'Scope filter',
                    prefixIcon: Icon(Icons.filter_alt_outlined),
                  ),
                  onChanged: (value) {
                    ref.read(memoryScopeProvider.notifier).state = value.trim();
                  },
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Add memory', style: theme.textTheme.titleMedium),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _keyController,
                    decoration: const InputDecoration(labelText: 'Key'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _valueController,
                    minLines: 2,
                    maxLines: 4,
                    decoration: const InputDecoration(labelText: 'Value'),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _scopeController,
                          decoration: const InputDecoration(labelText: 'Scope'),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: TextField(
                          controller: _tagsController,
                          decoration: const InputDecoration(labelText: 'Tags'),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Align(
                    alignment: Alignment.centerRight,
                    child: FilledButton.icon(
                      onPressed: _saving ? null : _createMemory,
                      icon: _saving
                          ? const SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.add),
                      label: const Text('Save'),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          Expanded(
            child: memories.when(
              data: (items) {
                if (items.isEmpty) {
                  return const Center(child: Text('No memory entries found'));
                }
                return ListView.separated(
                  itemCount: items.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 12),
                  itemBuilder: (context, index) {
                    final item = items[index];
                    return Card(
                      child: ListTile(
                        contentPadding: const EdgeInsets.all(16),
                        title: Text((item['key'] ?? '').toString()),
                        subtitle: Padding(
                          padding: const EdgeInsets.only(top: 8),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              SelectableText((item['value'] ?? '').toString()),
                              const SizedBox(height: 8),
                              Wrap(
                                spacing: 8,
                                runSpacing: 8,
                                children: [
                                  Chip(label: Text('scope: ${(item['scope'] ?? 'global')}')),
                                  if ((item['tags'] ?? '').toString().isNotEmpty)
                                    Chip(label: Text('tags: ${item['tags']}')),
                                ],
                              ),
                            ],
                          ),
                        ),
                        trailing: IconButton(
                          icon: const Icon(Icons.delete_outline),
                          onPressed: () => _deleteMemory((item['id'] ?? '').toString()),
                        ),
                      ),
                    );
                  },
                );
              },
              loading: () => const Center(child: CircularProgressIndicator()),
              error: (error, _) => Center(child: Text('Error: $error')),
            ),
          ),
        ],
      ),
    );
  }
}
