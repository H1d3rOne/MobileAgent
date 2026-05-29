import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/services/api_service.dart';

class DecompiledTree extends ConsumerStatefulWidget {
  final String rootDir;
  const DecompiledTree({super.key, required this.rootDir});

  @override
  ConsumerState<DecompiledTree> createState() => _DecompiledTreeState();
}

class _DecompiledTreeState extends ConsumerState<DecompiledTree> {
  String? _filePreviewPath;
  String? _filePreviewContent;
  bool _previewLoading = false;

  Future<List<_FileEntry>> _loadDir(String dir) async {
    final api = ref.read(apiServiceProvider);
    final res = await api.browseDir(dir);
    final entries = (res['entries'] as List? ?? [])
        .cast<Map<String, dynamic>>()
        .map(_FileEntry.fromJson)
        .toList();
    return entries;
  }

  Future<void> _previewFile(String dir, String name) async {
    setState(() {
      _previewLoading = true;
      _filePreviewPath = '$dir/$name';
      _filePreviewContent = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.browseFile(dir, name);
      setState(() {
        _filePreviewContent = (res['content'] ?? '').toString();
        _previewLoading = false;
      });
    } catch (e) {
      setState(() {
        _filePreviewContent = 'Error: $e';
        _previewLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SizedBox(
          width: 360,
          child: SingleChildScrollView(
            child: _DirNode(
              dir: widget.rootDir,
              label: widget.rootDir.split('/').last,
              depth: 0,
              loadDir: _loadDir,
              onFileTap: _previewFile,
            ),
          ),
        ),
        const VerticalDivider(width: 1),
        Expanded(
          child: _filePreviewPath == null
              ? Center(
                  child: Text('Select a file to preview',
                      style: theme.textTheme.bodyMedium
                          ?.copyWith(color: Colors.grey)),
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Padding(
                      padding: const EdgeInsets.all(12),
                      child: SelectableText(
                        _filePreviewPath!,
                        style: theme.textTheme.bodySmall
                            ?.copyWith(fontFamily: 'monospace'),
                      ),
                    ),
                    const Divider(height: 1),
                    Expanded(
                      child: _previewLoading
                          ? const Center(child: CircularProgressIndicator())
                          : SingleChildScrollView(
                              padding: const EdgeInsets.all(12),
                              child: SelectableText(
                                _filePreviewContent ?? '',
                                style: theme.textTheme.bodySmall
                                    ?.copyWith(fontFamily: 'monospace'),
                              ),
                            ),
                    ),
                  ],
                ),
        ),
      ],
    );
  }
}

class _DirNode extends StatefulWidget {
  final String dir;
  final String label;
  final int depth;
  final Future<List<_FileEntry>> Function(String dir) loadDir;
  final void Function(String dir, String name) onFileTap;

  const _DirNode({
    required this.dir,
    required this.label,
    required this.depth,
    required this.loadDir,
    required this.onFileTap,
  });

  @override
  State<_DirNode> createState() => _DirNodeState();
}

class _DirNodeState extends State<_DirNode> {
  bool _expanded = false;
  bool _loading = false;
  List<_FileEntry>? _entries;
  String? _error;

  Future<void> _toggle() async {
    if (_expanded) {
      setState(() => _expanded = false);
      return;
    }
    if (_entries == null) {
      setState(() => _loading = true);
      try {
        final entries = await widget.loadDir(widget.dir);
        setState(() {
          _entries = entries;
          _loading = false;
          _expanded = true;
        });
      } catch (e) {
        setState(() {
          _error = e.toString();
          _loading = false;
          _expanded = true;
        });
      }
    } else {
      setState(() => _expanded = true);
    }
  }

  @override
  void initState() {
    super.initState();
    if (widget.depth == 0) {
      _toggle();
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final indent = widget.depth * 12.0;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        InkWell(
          onTap: _toggle,
          child: Padding(
            padding:
                EdgeInsets.only(left: indent, top: 4, bottom: 4, right: 8),
            child: Row(
              children: [
                Icon(
                  _expanded ? Icons.expand_more : Icons.chevron_right,
                  size: 16,
                ),
                Icon(Icons.folder,
                    size: 14, color: theme.colorScheme.primary),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(
                    widget.label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodySmall,
                  ),
                ),
                if (_loading)
                  const SizedBox(
                    width: 12,
                    height: 12,
                    child: CircularProgressIndicator(strokeWidth: 1.5),
                  ),
              ],
            ),
          ),
        ),
        if (_expanded && _error != null)
          Padding(
            padding: EdgeInsets.only(left: indent + 24, right: 8),
            child: Text(_error!,
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: theme.colorScheme.error)),
          ),
        if (_expanded && _entries != null)
          ..._entries!.map((e) {
            if (e.isDir) {
              return _DirNode(
                dir: e.path,
                label: e.name,
                depth: widget.depth + 1,
                loadDir: widget.loadDir,
                onFileTap: widget.onFileTap,
              );
            }
            return InkWell(
              onTap: () => widget.onFileTap(widget.dir, e.name),
              child: Padding(
                padding: EdgeInsets.only(
                    left: indent + 24, top: 3, bottom: 3, right: 8),
                child: Row(
                  children: [
                    const Icon(Icons.insert_drive_file,
                        size: 13, color: Colors.grey),
                    const SizedBox(width: 4),
                    Expanded(
                      child: Text(
                        e.name,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.bodySmall,
                      ),
                    ),
                  ],
                ),
              ),
            );
          }),
      ],
    );
  }
}

class _FileEntry {
  final String name;
  final String path;
  final bool isDir;
  final int size;

  _FileEntry({
    required this.name,
    required this.path,
    required this.isDir,
    required this.size,
  });

  factory _FileEntry.fromJson(Map<String, dynamic> json) => _FileEntry(
        name: (json['name'] ?? '').toString(),
        path: (json['path'] ?? '').toString(),
        isDir: json['is_dir'] == true,
        size: (json['size'] is int) ? json['size'] as int : 0,
      );
}
