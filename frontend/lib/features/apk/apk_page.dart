import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';

import '../../core/providers/apk_provider.dart';
import '../../core/models/apk_model.dart';
import 'widgets/result_panel.dart';
import 'widgets/build_sign_install_tab.dart';
import 'widgets/native_components_tab.dart';
import 'widgets/network_tab.dart';
import 'widgets/decompiled_tree.dart';
import 'widgets/analysis_renderers.dart' as renderers;
import 'widgets/report_view.dart';
import 'widgets/hooks_view.dart';
import 'widgets/callgraph_view.dart';
import 'widgets/diff_view.dart';

const _analyzerTitles = {
  'manifest': 'Manifest',
  'certificate': 'Certificate',
  'risk': 'Risk Scan',
  'code': 'Code Scan',
  'sdk': 'Third-party SDKs',
  'strings': 'Strings & Config',
  'antidetect': 'Anti-Detection',
};

class ApkPage extends ConsumerStatefulWidget {
  const ApkPage({super.key});
  @override
  ConsumerState<ApkPage> createState() => _ApkPageState();
}

class _ApkPageState extends ConsumerState<ApkPage>
    with SingleTickerProviderStateMixin {
  late final TabController _tabController =
      TabController(length: 8, vsync: this);
  String _decompileTool = 'apktool';
  String _analysisAction = 'manifest';
  final _searchController = TextEditingController();
  String _searchQuery = '';

  @override
  void dispose() {
    _tabController.dispose();
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(apkProvider);
    final theme = Theme.of(context);

    return Scaffold(
      body: Column(
        children: [
          if (state.error != null)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              color: theme.colorScheme.error.withValues(alpha: 0.1),
              child: Row(
                children: [
                  Icon(Icons.error_outline,
                      color: theme.colorScheme.error, size: 18),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(state.error!,
                        style: TextStyle(
                            color: theme.colorScheme.error, fontSize: 13)),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close, size: 16),
                    onPressed: () =>
                        ref.read(apkProvider.notifier).clearError(),
                  ),
                ],
              ),
            ),
          Expanded(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                SizedBox(width: 320, child: _buildLeftPanel(state, theme)),
                const VerticalDivider(width: 1),
                Expanded(child: _buildRightPanel(state, theme)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLeftPanel(ApkState state, ThemeData theme) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 8, 0),
          child: Row(
            children: [
              Text('APKs', style: theme.textTheme.titleMedium),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.refresh, size: 18),
                tooltip: 'Refresh',
                visualDensity: VisualDensity.compact,
                onPressed: () =>
                    ref.read(apkProvider.notifier).refreshApks(),
              ),
            ],
          ),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: SizedBox(
            width: double.infinity,
            height: 34,
            child: FilledButton.icon(
              onPressed: state.loading ? null : _pickAndUploadApk,
              icon: state.loading
                  ? const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                    )
                  : const Icon(Icons.upload_file, size: 16),
              label: Text(state.loading ? 'Uploading…' : 'Upload APK', style: const TextStyle(fontSize: 13)),
            ),
          ),
        ),
        if (state.apks.length > 3)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                hintText: 'Filter APKs...',
                prefixIcon: const Icon(Icons.search, size: 16),
                suffixIcon: _searchQuery.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.close, size: 14),
                        onPressed: () {
                          _searchController.clear();
                          setState(() => _searchQuery = '');
                        },
                      )
                    : null,
                border: const OutlineInputBorder(),
                isDense: true,
                contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              ),
              style: const TextStyle(fontSize: 12),
              onChanged: (v) => setState(() => _searchQuery = v.toLowerCase()),
            ),
          ),
        const Divider(height: 1),
        Expanded(
          child: state.apks.isEmpty
              ? Center(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.android_outlined,
                            size: 48, color: Colors.grey[400]),
                        const SizedBox(height: 12),
                        Text('No APKs uploaded',
                            style: theme.textTheme.bodyMedium
                                ?.copyWith(color: Colors.grey)),
                      ],
                    ),
                  ),
                )
              : Builder(builder: (context) {
                  final filtered = _searchQuery.isEmpty
                      ? state.apks
                      : state.apks.where((a) =>
                          a.packageName.toLowerCase().contains(_searchQuery) ||
                          a.path.split('/').last.toLowerCase().contains(_searchQuery)).toList();
                  if (filtered.isEmpty) {
                    return Center(
                      child: Text('No matches for "$_searchQuery"',
                          style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
                    );
                  }
                  return ListView.builder(
                  itemCount: filtered.length,
                  itemBuilder: (context, index) {
                    final apk = filtered[index];
                    final isSelected = state.selected?.path == apk.path;
                    final decompiled =
                        (apk.decompiledPath ?? '').isNotEmpty;
                    final fileName = apk.path.split('/').last;
                    final sizeStr = _formatSize(apk.fileSize);
                    return ListTile(
                      dense: true,
                      visualDensity: const VisualDensity(vertical: -2),
                      selected: isSelected,
                      selectedTileColor: theme.colorScheme.primary
                          .withValues(alpha: 0.12),
                      leading: Icon(Icons.android, size: 20,
                          color: isSelected ? theme.colorScheme.primary : null),
                      title: Text(
                        apk.packageName.isEmpty ? fileName : apk.packageName,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
                        ),
                      ),
                      subtitle: Row(
                        children: [
                          Text(
                              'v${apk.versionName.isEmpty ? "?" : apk.versionName}',
                              style: theme.textTheme.labelSmall?.copyWith(color: Colors.grey)),
                          const SizedBox(width: 6),
                          Text(sizeStr,
                              style: theme.textTheme.labelSmall?.copyWith(color: Colors.grey)),
                          if (decompiled) ...[
                            const SizedBox(width: 6),
                            Icon(Icons.code,
                                size: 11,
                                color: theme.colorScheme.primary),
                          ],
                        ],
                      ),
                      trailing: IconButton(
                        icon: const Icon(Icons.close, size: 14),
                        tooltip: 'Remove',
                        visualDensity: VisualDensity.compact,
                        onPressed: () =>
                            ref.read(apkProvider.notifier).removeApk(apk),
                      ),
                      onTap: () =>
                          ref.read(apkProvider.notifier).selectApk(apk),
                    );
                  },
                );
                }),
        ),
      ],
    );
  }

  Widget _buildRightPanel(ApkState state, ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (state.selected == null)
          Expanded(
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.android_outlined, size: 64, color: Colors.grey[400]),
                  const SizedBox(height: 16),
                  Text('Select an APK to begin', style: theme.textTheme.titleLarge),
                  const SizedBox(height: 8),
                  Text(
                      'Upload an APK on the left, then choose Decompile or Analysis.',
                      style: theme.textTheme.bodySmall),
                ],
              ),
            ),
          )
        else ...[
          _buildHeader(state.selected!, theme),
          const Divider(height: 1),
          TabBar(
            controller: _tabController,
            isScrollable: true,
            tabAlignment: TabAlignment.start,
            labelPadding: const EdgeInsets.symmetric(horizontal: 12),
            tabs: const [
              Tab(height: 36, icon: Icon(Icons.code, size: 14), iconMargin: EdgeInsets.only(bottom: 0), text: 'Decompile'),
              Tab(height: 36, icon: Icon(Icons.analytics, size: 14), iconMargin: EdgeInsets.only(bottom: 0), text: 'Analysis'),
              Tab(height: 36, icon: Icon(Icons.build_outlined, size: 14), iconMargin: EdgeInsets.only(bottom: 0), text: 'Build'),
              Tab(height: 36, icon: Icon(Icons.key, size: 14), iconMargin: EdgeInsets.only(bottom: 0), text: 'Sign'),
              Tab(height: 36, icon: Icon(Icons.install_mobile, size: 14), iconMargin: EdgeInsets.only(bottom: 0), text: 'Install'),
              Tab(height: 36, icon: Icon(Icons.memory, size: 14), iconMargin: EdgeInsets.only(bottom: 0), text: 'Native'),
              Tab(height: 36, icon: Icon(Icons.bug_report, size: 14), iconMargin: EdgeInsets.only(bottom: 0), text: 'Components'),
              Tab(height: 36, icon: Icon(Icons.wifi_tethering, size: 14), iconMargin: EdgeInsets.only(bottom: 0), text: 'Network'),
            ],
          ),
          const Divider(height: 1),
          Expanded(
            child: AnimatedBuilder(
              animation: _tabController,
              builder: (context, _) {
                switch (_tabController.index) {
                  case 0:
                    return Column(
                      children: [
                        _buildDecompileMenu(state, theme),
                        const Divider(height: 1),
                        Expanded(child: _buildDecompileWorkspace(state, theme)),
                      ],
                    );
                  case 1:
                    return Column(
                      children: [
                        _buildAnalysisMenu(state, theme),
                        const Divider(height: 1),
                        Expanded(child: _buildAnalysisWorkspace(state, theme)),
                      ],
                    );
                  case 2:
                    return const BuildTab();
                  case 3:
                    return const SignTab();
                  case 4:
                    return const InstallTab();
                  case 5:
                    return const NativeTab();
                  case 6:
                    return const ComponentsTab();
                  case 7:
                    return const NetworkTab();
                  default:
                    return const SizedBox.shrink();
                }
              },
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildHeader(ApkInfo apk, ThemeData theme) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Row(
        children: [
          Icon(Icons.android, color: theme.colorScheme.primary, size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              apk.packageName.isEmpty ? apk.path.split('/').last : apk.packageName,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.titleSmall,
            ),
          ),
          const SizedBox(width: 8),
          _infoChip('v${apk.versionName.isEmpty ? "?" : apk.versionName}', theme),
          if (apk.permissions.isNotEmpty)
            _infoChip('${apk.permissions.length} perms', theme),
          if (apk.nativeLibs.isNotEmpty)
            _infoChip('${apk.nativeLibs.length} libs', theme),
          _infoChip(_formatSize(apk.fileSize), theme),
        ],
      ),
    );
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

  Widget _buildDecompileMenu(ApkState state, ThemeData theme) {
    final isRunning = state.decompileStatus == 'Decompiling...';
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          MenuButton(
            icon: Icons.build,
            label: 'Apktool',
            selected: _decompileTool == 'apktool',
            running: isRunning && _decompileTool == 'apktool',
            hasResult: state.decompileTool == 'apktool' &&
                state.decompileStatus == 'Done',
            onPressed: isRunning
                ? null
                : () {
                    setState(() => _decompileTool = 'apktool');
                    ref.read(apkProvider.notifier).decompile(
                        state.selected!.path,
                        tool: 'apktool');
                  },
          ),
          MenuButton(
            icon: Icons.code,
            label: 'JADX',
            selected: _decompileTool == 'jadx',
            running: isRunning && _decompileTool == 'jadx',
            hasResult: state.decompileTool == 'jadx' &&
                state.decompileStatus == 'Done',
            onPressed: isRunning
                ? null
                : () {
                    setState(() => _decompileTool = 'jadx');
                    ref.read(apkProvider.notifier).decompile(
                        state.selected!.path,
                        tool: 'jadx');
                  },
          ),
        ],
      ),
    );
  }

  Widget _buildAnalysisMenu(ApkState state, ThemeData theme) {
    final apk = state.selected!;
    final hasDecompile = (apk.decompiledPath ?? '').isNotEmpty;
    final notifier = ref.read(apkProvider.notifier);
    final allRunning =
        analysisTypes.every((t) => state.runningAnalyzers.contains(t));

    Widget btn(String type, String label, IconData icon, {bool disabled = false}) {
      final running = state.runningAnalyzers.contains(type);
      final hasResult = state.analyses[type] != null;
      return MenuButton(
        icon: icon,
        label: label,
        selected: _analysisAction == type,
        running: running,
        hasResult: hasResult,
        onPressed: disabled
            ? null
            : () {
                setState(() => _analysisAction = type);
                if (!hasResult && !running) {
                  notifier.runAnalyzer(type);
                }
              },
      );
    }

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          btn('manifest', 'Manifest', Icons.description),
          btn('certificate', 'Certificate', Icons.verified_user),
          btn('risk', 'Risk', Icons.warning_amber),
          btn('code', 'Code', Icons.policy, disabled: !hasDecompile),
          btn('sdk', 'SDKs', Icons.extension, disabled: !hasDecompile),
          btn('strings', 'Strings', Icons.text_fields, disabled: !hasDecompile),
          btn('antidetect', 'Protection', Icons.shield, disabled: !hasDecompile),
          MenuButton(
            icon: Icons.play_circle,
            label: 'Run All',
            selected: false,
            running: allRunning,
            primary: true,
            onPressed: allRunning ? null : () => notifier.runAllAnalyzers(),
          ),
          MenuButton(
            icon: Icons.assessment,
            label: 'Report',
            selected: _analysisAction == 'report',
            running: false,
            hasResult: false,
            primary: true,
            onPressed: () => setState(() => _analysisAction = 'report'),
          ),
          MenuButton(
            icon: Icons.auto_fix_high,
            label: 'Hooks',
            selected: _analysisAction == 'hooks',
            running: false,
            hasResult: false,
            primary: true,
            onPressed: () => setState(() => _analysisAction = 'hooks'),
          ),
          MenuButton(
            icon: Icons.account_tree,
            label: 'Call Graph',
            selected: _analysisAction == 'callgraph',
            running: false,
            hasResult: false,
            primary: true,
            onPressed: !hasDecompile
                ? null
                : () => setState(() => _analysisAction = 'callgraph'),
          ),
          if (state.apks.length > 1)
            MenuButton(
              icon: Icons.compare_arrows,
              label: 'Diff',
              selected: _analysisAction == 'diff',
              running: false,
              hasResult: false,
              primary: true,
              onPressed: () => setState(() => _analysisAction = 'diff'),
            ),
        ],
      ),
    );
  }

  Widget _buildDecompileWorkspace(ApkState state, ThemeData theme) {
    final isRunning = state.decompileStatus == 'Decompiling...';
    final outputDir = state.decompileOutputDir;
    final hasOutput =
        (outputDir ?? '').isNotEmpty && state.decompileStatus == 'Done';
    final failed = state.decompileStatus == 'Failed';

    if (isRunning) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 12),
            Text('Decompiling with $_decompileTool…',
                style: theme.textTheme.bodyMedium),
          ],
        ),
      );
    }
    if (failed) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline,
                  size: 48, color: theme.colorScheme.error),
              const SizedBox(height: 12),
              Text('Decompile failed',
                  style: theme.textTheme.titleMedium),
              const SizedBox(height: 4),
              Text('Try the other tool, or check that apktool/jadx is installed.',
                  style: theme.textTheme.bodySmall),
            ],
          ),
        ),
      );
    }
    if (!hasOutput) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            'Click Apktool or JADX above to decompile this APK. The extracted file tree will appear here.',
            style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey),
            textAlign: TextAlign.center,
          ),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Row(
            children: [
              const Icon(Icons.check_circle, size: 14, color: Colors.green),
              const SizedBox(width: 6),
              Text('Tool: ${state.decompileTool}',
                  style: theme.textTheme.bodySmall),
              const SizedBox(width: 12),
              Expanded(
                child: SelectableText(
                  outputDir!,
                  maxLines: 1,
                  style: theme.textTheme.bodySmall
                      ?.copyWith(fontFamily: 'monospace', color: Colors.grey),
                ),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(child: DecompiledTree(rootDir: outputDir)),
      ],
    );
  }

  Widget _buildAnalysisWorkspace(ApkState state, ThemeData theme) {
    if (_analysisAction == 'report') {
      return const ReportView();
    }
    if (_analysisAction == 'hooks') {
      return const HooksView();
    }
    if (_analysisAction == 'callgraph') {
      return const CallGraphView();
    }
    if (_analysisAction == 'diff') {
      return const DiffView();
    }

    final type = _analysisAction;
    final running = state.runningAnalyzers.contains(type);
    final error = state.analyzerErrors[type];
    final raw = state.analyses[type];
    final data = raw is Map<String, dynamic>
        ? raw
        : (raw is Map ? raw.cast<String, dynamic>() : null);
    final title = _analyzerTitles[type] ?? type;
    final notifier = ref.read(apkProvider.notifier);

    Widget headerBar() {
      return Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(
          children: [
            Text(title, style: theme.textTheme.titleMedium),
            const SizedBox(width: 8),
            if (running)
              const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(strokeWidth: 1.5),
              )
            else if (data != null)
              const Icon(Icons.check_circle, size: 14, color: Colors.green)
            else if (error != null)
              Icon(Icons.error_outline,
                  size: 14, color: theme.colorScheme.error),
            const Spacer(),
            if (data != null && !running)
              TextButton.icon(
                onPressed: () => notifier.runAnalyzer(type),
                icon: const Icon(Icons.refresh, size: 14),
                label: const Text('Re-run'),
              ),
          ],
        ),
      );
    }

    if (running && data == null) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          headerBar(),
          const Divider(height: 1),
          Expanded(
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const CircularProgressIndicator(),
                  const SizedBox(height: 12),
                  Text('Running $title…',
                      style: theme.textTheme.bodyMedium),
                ],
              ),
            ),
          ),
        ],
      );
    }

    if (error != null && data == null) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          headerBar(),
          const Divider(height: 1),
          Expanded(
            child: Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.error_outline,
                        size: 36, color: theme.colorScheme.error),
                    const SizedBox(height: 8),
                    Text(error,
                        textAlign: TextAlign.center,
                        style: theme.textTheme.bodySmall
                            ?.copyWith(color: theme.colorScheme.error)),
                    const SizedBox(height: 12),
                    FilledButton.tonalIcon(
                      onPressed: () => notifier.runAnalyzer(type),
                      icon: const Icon(Icons.refresh, size: 14),
                      label: const Text('Try again'),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      );
    }

    if (data == null) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          headerBar(),
          const Divider(height: 1),
          Expanded(
            child: Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text('No data yet for $title.',
                        style: theme.textTheme.bodyMedium
                            ?.copyWith(color: Colors.grey)),
                    const SizedBox(height: 12),
                    FilledButton.icon(
                      onPressed: () => notifier.runAnalyzer(type),
                      icon: const Icon(Icons.play_arrow, size: 16),
                      label: Text('Run $title'),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        headerBar(),
        if (error != null)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Text('Last run failed: $error',
                style: TextStyle(
                    color: theme.colorScheme.error, fontSize: 12)),
          ),
        const Divider(height: 1),
        Expanded(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: renderers.renderAnalyzer(type, data, theme),
          ),
        ),
      ],
    );
  }
  Future<void> _pickAndUploadApk() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.any,
        withData: true,
      );
      if (result == null || result.files.isEmpty) return;
      final file = result.files.single;
      final String? localPath = kIsWeb ? null : file.path;
      if (file.bytes == null && localPath == null) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Failed to read file content')),
          );
        }
        return;
      }
      if (!file.name.toLowerCase().endsWith('.apk')) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Not an APK file: ${file.name}')),
          );
        }
        return;
      }
      await ref.read(apkProvider.notifier).uploadAndAnalyze(
            file.name,
            filePath: localPath,
            bytes: file.bytes,
          );
      if (mounted) {
        _tabController.animateTo(1);
        setState(() => _analysisAction = 'manifest');
      }
    } catch (e, st) {
      debugPrint('APK pick/upload failed: $e\n$st');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Upload failed: $e')),
        );
      }
    }
  }

  String _formatSize(int bytes) {
    if (bytes <= 0) return '';
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(0)}KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
  }
}

