import 'dart:convert';

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';

import '../../core/providers/apk_provider.dart';
import '../../core/models/apk_model.dart';
import '../../core/services/api_service.dart';

const _analyzerTitles = {
  'manifest': 'Manifest',
  'certificate': 'Certificate',
  'risk': 'Risk Scan',
  'attack_surface': 'Attack Surface',
  'entry_trace': 'Entry Trace',
  'packer': 'Packer / Protection',
  'code': 'Code Scan',
  'sdk': 'Third-party SDKs',
  'strings': 'Strings & Config',
  'antidetect': 'Anti-Detection',
  'triage': 'Agent Triage',
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
  final _buildPathController = TextEditingController();
  final _signPathController = TextEditingController();
  final _signKeystoreController = TextEditingController();
  final _signAliasController = TextEditingController();
  final _installSerialController = TextEditingController();
  final _r2FileController = TextEditingController();
  final _androguardCmdController = TextEditingController();
  final _mitmportController = TextEditingController(text: '8080');
  final _searchController = TextEditingController();
  String _searchQuery = '';
  String? _r2Result;
  String? _androguardResult;
  String? _mitmResult;
  bool _r2Running = false;
  bool _androguardRunning = false;
  bool _mitmRunning = false;
  String? _buildResult;
  String? _signResult;
  String? _installResult;
  bool _buildRunning = false;
  bool _signRunning = false;
  bool _installRunning = false;
  bool _reportRunning = false;
  Map<String, dynamic>? _reportData;
  bool _evidencePackageRunning = false;
  bool _hooksRunning = false;
  List<Map<String, dynamic>>? _hooksData;
  bool _runtimePlanRunning = false;
  Map<String, dynamic>? _runtimePlanData;
  bool _reversePlanRunning = false;
  Map<String, dynamic>? _reversePlanData;
  Map<String, dynamic>? _reverseValidateData;
  bool _callgraphRunning = false;
  Map<String, dynamic>? _callgraphData;
  List<Map<String, dynamic>>? _fridaScripts;
  List<String>? _fridaCategories;
  String? _fridaSelectedCategory;
  String? _fridaSelectedScript;
  bool _fridaLoading = false;
  bool _fridaRunning = false;
  String? _fridaRunOutput;
  Map<String, dynamic>? _fridaEvidenceData;
  bool _fridaEvidencePersisted = false;
  String? _fridaEvidencePersistError;
  final _fridaSerialController = TextEditingController();
  final _fridaTargetController = TextEditingController();
  bool _diffRunning = false;
  Map<String, dynamic>? _diffData;
  String? _diffTargetId;

  @override
  void dispose() {
    _tabController.dispose();
    _buildPathController.dispose();
    _signPathController.dispose();
    _signKeystoreController.dispose();
    _signAliasController.dispose();
    _installSerialController.dispose();
    _r2FileController.dispose();
    _androguardCmdController.dispose();
    _mitmportController.dispose();
    _searchController.dispose();
    _fridaSerialController.dispose();
    _fridaTargetController.dispose();
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
                onPressed: () => ref.read(apkProvider.notifier).refreshApks(),
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
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: Colors.white),
                    )
                  : const Icon(Icons.upload_file, size: 16),
              label: Text(state.loading ? 'Uploading…' : 'Upload APK',
                  style: const TextStyle(fontSize: 13)),
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
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
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
                      : state.apks
                          .where((a) =>
                              a.packageName
                                  .toLowerCase()
                                  .contains(_searchQuery) ||
                              a.path
                                  .split('/')
                                  .last
                                  .toLowerCase()
                                  .contains(_searchQuery))
                          .toList();
                  if (filtered.isEmpty) {
                    return Center(
                      child: Text('No matches for "$_searchQuery"',
                          style: theme.textTheme.bodySmall
                              ?.copyWith(color: Colors.grey)),
                    );
                  }
                  return ListView.builder(
                    itemCount: filtered.length,
                    itemBuilder: (context, index) {
                      final apk = filtered[index];
                      final isSelected = state.selected?.path == apk.path;
                      final decompiled = (apk.decompiledPath ?? '').isNotEmpty;
                      final fileName = apk.path.split('/').last;
                      final sizeStr = _formatSize(apk.fileSize);
                      return ListTile(
                        dense: true,
                        visualDensity: const VisualDensity(vertical: -2),
                        selected: isSelected,
                        selectedTileColor:
                            theme.colorScheme.primary.withValues(alpha: 0.12),
                        leading: Icon(Icons.android,
                            size: 20,
                            color:
                                isSelected ? theme.colorScheme.primary : null),
                        title: Text(
                          apk.packageName.isEmpty ? fileName : apk.packageName,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.bodySmall?.copyWith(
                            fontWeight:
                                isSelected ? FontWeight.w600 : FontWeight.w500,
                          ),
                        ),
                        subtitle: Row(
                          children: [
                            Text(
                                'v${apk.versionName.isEmpty ? "?" : apk.versionName}',
                                style: theme.textTheme.labelSmall
                                    ?.copyWith(color: Colors.grey)),
                            const SizedBox(width: 6),
                            Text(sizeStr,
                                style: theme.textTheme.labelSmall
                                    ?.copyWith(color: Colors.grey)),
                            if (decompiled) ...[
                              const SizedBox(width: 6),
                              Icon(Icons.code,
                                  size: 11, color: theme.colorScheme.primary),
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
                  Icon(Icons.android_outlined,
                      size: 64, color: Colors.grey[400]),
                  const SizedBox(height: 16),
                  Text('Select an APK to begin',
                      style: theme.textTheme.titleLarge),
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
              Tab(
                  height: 36,
                  icon: Icon(Icons.code, size: 14),
                  iconMargin: EdgeInsets.only(bottom: 0),
                  text: 'Decompile'),
              Tab(
                  height: 36,
                  icon: Icon(Icons.analytics, size: 14),
                  iconMargin: EdgeInsets.only(bottom: 0),
                  text: 'Analysis'),
              Tab(
                  height: 36,
                  icon: Icon(Icons.build_outlined, size: 14),
                  iconMargin: EdgeInsets.only(bottom: 0),
                  text: 'Build'),
              Tab(
                  height: 36,
                  icon: Icon(Icons.key, size: 14),
                  iconMargin: EdgeInsets.only(bottom: 0),
                  text: 'Sign'),
              Tab(
                  height: 36,
                  icon: Icon(Icons.install_mobile, size: 14),
                  iconMargin: EdgeInsets.only(bottom: 0),
                  text: 'Install'),
              Tab(
                  height: 36,
                  icon: Icon(Icons.memory, size: 14),
                  iconMargin: EdgeInsets.only(bottom: 0),
                  text: 'Native'),
              Tab(
                  height: 36,
                  icon: Icon(Icons.bug_report, size: 14),
                  iconMargin: EdgeInsets.only(bottom: 0),
                  text: 'Components'),
              Tab(
                  height: 36,
                  icon: Icon(Icons.wifi_tethering, size: 14),
                  iconMargin: EdgeInsets.only(bottom: 0),
                  text: 'Network'),
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
                    return _buildBuildTab(state, theme);
                  case 3:
                    return _buildSignTab(state, theme);
                  case 4:
                    return _buildInstallTab(state, theme);
                  case 5:
                    return _buildRadare2Tab(state, theme);
                  case 6:
                    return _buildAndroguardTab(state, theme);
                  case 7:
                    return _buildMitmproxyTab(state, theme);
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
              apk.packageName.isEmpty
                  ? apk.path.split('/').last
                  : apk.packageName,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.titleSmall,
            ),
          ),
          const SizedBox(width: 8),
          _infoChip(
              'v${apk.versionName.isEmpty ? "?" : apk.versionName}', theme),
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
        child: Text(label,
            style: TextStyle(
                fontSize: 10,
                color: theme.colorScheme.onSurface.withValues(alpha: 0.7))),
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
          _MenuButton(
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
                    ref
                        .read(apkProvider.notifier)
                        .decompile(state.selected!.path, tool: 'apktool');
                  },
          ),
          _MenuButton(
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
                    ref
                        .read(apkProvider.notifier)
                        .decompile(state.selected!.path, tool: 'jadx');
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

    Widget btn(String type, String label, IconData icon,
        {bool disabled = false}) {
      final running = state.runningAnalyzers.contains(type);
      final hasResult = state.analyses[type] != null;
      return _MenuButton(
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
          btn('attack_surface', 'Attack Surface', Icons.hub),
          btn('entry_trace', 'Entry Trace', Icons.route,
              disabled: !hasDecompile),
          _MenuButton(
            icon: Icons.psychology_alt,
            label: 'Triage',
            selected: _analysisAction == 'triage',
            running: state.runningAnalyzers.contains('triage'),
            hasResult: state.analyses['triage'] != null,
            primary: true,
            onPressed: () {
              setState(() => _analysisAction = 'triage');
              if (!state.runningAnalyzers.contains('triage')) {
                notifier.runTriage(includeCallgraph: hasDecompile);
              }
            },
          ),
          btn('packer', 'Packer', Icons.inventory_2, disabled: !hasDecompile),
          btn('code', 'Code', Icons.policy, disabled: !hasDecompile),
          btn('sdk', 'SDKs', Icons.extension, disabled: !hasDecompile),
          btn('strings', 'Strings', Icons.text_fields, disabled: !hasDecompile),
          btn('antidetect', 'Protection', Icons.shield,
              disabled: !hasDecompile),
          _MenuButton(
            icon: Icons.play_circle,
            label: 'Run All',
            selected: false,
            running: allRunning,
            primary: true,
            onPressed: allRunning ? null : () => notifier.runAllAnalyzers(),
          ),
          _MenuButton(
            icon: Icons.assessment,
            label: 'Report',
            selected: _analysisAction == 'report',
            running: _reportRunning,
            hasResult: _reportData != null,
            primary: true,
            onPressed: _reportRunning
                ? null
                : () {
                    setState(() => _analysisAction = 'report');
                    if (_reportData == null) _generateReport(apk);
                  },
          ),
          _MenuButton(
            icon: Icons.auto_fix_high,
            label: 'Hooks',
            selected: _analysisAction == 'hooks',
            running: _hooksRunning,
            hasResult: _hooksData != null,
            primary: true,
            onPressed: _hooksRunning
                ? null
                : () {
                    setState(() => _analysisAction = 'hooks');
                    if (_hooksData == null) _generateHooks(apk);
                  },
          ),
          _MenuButton(
            icon: Icons.fact_check,
            label: 'Runtime Plan',
            selected: _analysisAction == 'runtime_plan',
            running: _runtimePlanRunning,
            hasResult: _runtimePlanData != null,
            primary: true,
            onPressed: (!hasDecompile || _runtimePlanRunning)
                ? null
                : () {
                    setState(() => _analysisAction = 'runtime_plan');
                    if (_runtimePlanData == null) _generateRuntimePlan(apk);
                  },
          ),
          _MenuButton(
            icon: Icons.rule,
            label: 'Reverse Plan',
            selected: _analysisAction == 'reverse_plan',
            running: _reversePlanRunning,
            hasResult: _reversePlanData != null,
            primary: true,
            onPressed: (!hasDecompile || _reversePlanRunning)
                ? null
                : () {
                    setState(() => _analysisAction = 'reverse_plan');
                    if (_reversePlanData == null) _loadReversePlan(apk);
                  },
          ),
          _MenuButton(
            icon: Icons.account_tree,
            label: 'Call Graph',
            selected: _analysisAction == 'callgraph',
            running: _callgraphRunning,
            hasResult: _callgraphData != null,
            primary: true,
            onPressed: (!hasDecompile || _callgraphRunning)
                ? null
                : () {
                    setState(() => _analysisAction = 'callgraph');
                    if (_callgraphData == null) _loadCallGraph(apk);
                  },
          ),
          if (state.apks.length > 1)
            _MenuButton(
              icon: Icons.compare_arrows,
              label: 'Diff',
              selected: _analysisAction == 'diff',
              running: _diffRunning,
              hasResult: _diffData != null,
              primary: true,
              onPressed: _diffRunning
                  ? null
                  : () => setState(() => _analysisAction = 'diff'),
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
              Text('Decompile failed', style: theme.textTheme.titleMedium),
              const SizedBox(height: 4),
              Text(
                  'Try the other tool, or check that apktool/jadx is installed.',
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
        Expanded(child: _DecompiledTree(rootDir: outputDir)),
      ],
    );
  }

  Widget _buildAnalysisWorkspace(ApkState state, ThemeData theme) {
    if (_analysisAction == 'report') {
      return _buildReportView(theme);
    }
    if (_analysisAction == 'hooks') {
      return _buildHooksView(theme);
    }
    if (_analysisAction == 'runtime_plan') {
      return _buildRuntimePlanView(theme);
    }
    if (_analysisAction == 'reverse_plan') {
      return _buildReversePlanView(theme);
    }
    if (_analysisAction == 'callgraph') {
      return _buildCallGraphView(theme);
    }
    if (_analysisAction == 'diff') {
      return _buildDiffView(state, theme);
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
                  Text('Running $title…', style: theme.textTheme.bodyMedium),
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
                style: TextStyle(color: theme.colorScheme.error, fontSize: 12)),
          ),
        const Divider(height: 1),
        Expanded(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: _renderAnalyzer(type, data, theme),
          ),
        ),
      ],
    );
  }

  // =========================================================================
  // Build tab
  // =========================================================================

  Widget _buildBuildTab(ApkState state, ThemeData theme) {
    final apk = state.selected!;
    final decompiledPath = apk.decompiledPath ?? '';
    if (_buildPathController.text.isEmpty && decompiledPath.isNotEmpty) {
      _buildPathController.text = decompiledPath;
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _buildPathController,
                  decoration: const InputDecoration(
                    labelText: 'Decompiled project path',
                    hintText: '/path/to/decompiled/project',
                    border: OutlineInputBorder(),
                    isDense: true,
                    contentPadding:
                        EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  ),
                  style: const TextStyle(fontSize: 13),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                onPressed: _buildRunning ? null : () => _runBuild(state),
                icon: _buildRunning
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.build_outlined, size: 16),
                label: Text(_buildRunning ? 'Building...' : 'Build'),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: _ResultPanel(
              content: _buildResult,
              isRunning: _buildRunning,
              isError: _buildResult?.startsWith('Error') ?? false,
              emptyHint: 'Rebuild a decompiled APK project with apktool',
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _runBuild(ApkState state) async {
    final path = _buildPathController.text.trim();
    if (path.isEmpty) return;
    setState(() {
      _buildRunning = true;
      _buildResult = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.buildApk(path);
      setState(() {
        _buildResult = 'Built: ${res['output_path'] ?? res.toString()}';
        _buildRunning = false;
      });
    } catch (e) {
      setState(() {
        _buildResult = 'Error: $e';
        _buildRunning = false;
      });
    }
  }

  // =========================================================================
  // Sign tab
  // =========================================================================

  Widget _buildSignTab(ApkState state, ThemeData theme) {
    final apk = state.selected!;
    if (_signPathController.text.isEmpty) {
      _signPathController.text = apk.path;
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Column(
            children: [
              TextField(
                controller: _signPathController,
                decoration: const InputDecoration(
                  labelText: 'APK path',
                  border: OutlineInputBorder(),
                  isDense: true,
                  contentPadding:
                      EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                ),
                style: const TextStyle(fontSize: 13),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _signKeystoreController,
                      decoration: const InputDecoration(
                        labelText: 'Keystore (optional)',
                        hintText: 'debug key if empty',
                        border: OutlineInputBorder(),
                        isDense: true,
                        contentPadding:
                            EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      ),
                      style: const TextStyle(fontSize: 13),
                    ),
                  ),
                  const SizedBox(width: 8),
                  SizedBox(
                    width: 120,
                    child: TextField(
                      controller: _signAliasController,
                      decoration: const InputDecoration(
                        labelText: 'Alias',
                        border: OutlineInputBorder(),
                        isDense: true,
                        contentPadding:
                            EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      ),
                      style: const TextStyle(fontSize: 13),
                    ),
                  ),
                  const SizedBox(width: 8),
                  FilledButton.icon(
                    onPressed: _signRunning ? null : () => _runSign(),
                    icon: _signRunning
                        ? const SizedBox(
                            width: 14,
                            height: 14,
                            child: CircularProgressIndicator(
                                strokeWidth: 2, color: Colors.white))
                        : const Icon(Icons.key, size: 16),
                    label: Text(_signRunning ? 'Signing...' : 'Sign'),
                  ),
                ],
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: _ResultPanel(
              content: _signResult,
              isRunning: _signRunning,
              isError: _signResult?.startsWith('Error') ?? false,
              emptyHint: 'Sign APK with keystore or debug key',
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _runSign() async {
    final path = _signPathController.text.trim();
    if (path.isEmpty) return;
    setState(() {
      _signRunning = true;
      _signResult = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final ks = _signKeystoreController.text.trim();
      final alias = _signAliasController.text.trim();
      final res = await api.signApk(path,
          keystorePath: ks.isEmpty ? null : ks,
          keyAlias: alias.isEmpty ? null : alias);
      setState(() {
        _signResult = 'Signed: ${res['output_path'] ?? res.toString()}';
        _signRunning = false;
      });
    } catch (e) {
      setState(() {
        _signResult = 'Error: $e';
        _signRunning = false;
      });
    }
  }

  // =========================================================================
  // Install tab
  // =========================================================================

  Widget _buildInstallTab(ApkState state, ThemeData theme) {
    final apk = state.selected!;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _installSerialController,
                  decoration: const InputDecoration(
                    labelText: 'Device serial',
                    hintText: 'emulator-5554 or IP:port',
                    border: OutlineInputBorder(),
                    isDense: true,
                    contentPadding:
                        EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                onPressed: _installRunning ? null : () => _runInstall(apk),
                icon: _installRunning
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.install_mobile, size: 16),
                label: Text(_installRunning ? 'Installing...' : 'Install'),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: _ResultPanel(
              content: _installResult,
              isRunning: _installRunning,
              isError: _installResult?.startsWith('Error') ?? false,
              emptyHint: 'Install APK to device via ADB\nTarget: ${apk.path}',
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _runInstall(ApkInfo apk) async {
    final serial = _installSerialController.text.trim();
    if (serial.isEmpty) {
      setState(() => _installResult = 'Error: device serial is required');
      return;
    }
    setState(() {
      _installRunning = true;
      _installResult = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.installApk(serial, apk.path);
      setState(() {
        _installResult = res['message']?.toString() ?? 'Installed successfully';
        _installRunning = false;
      });
    } catch (e) {
      setState(() {
        _installResult = 'Error: $e';
        _installRunning = false;
      });
    }
  }

  // ===== Security Report =====

  Future<void> _generateReport(ApkInfo apk) async {
    if (apk.id == null) {
      setState(() {
        _reportData = {'error': 'APK has no ID'};
      });
      return;
    }
    setState(() {
      _reportRunning = true;
      _reportData = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.generateReport(apk.id!);
      setState(() {
        _reportData = res;
        _reportRunning = false;
      });
    } catch (e) {
      setState(() {
        _reportData = {'error': e.toString()};
        _reportRunning = false;
      });
    }
  }

  Widget _buildReportView(ThemeData theme) {
    if (_reportRunning) {
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

    if (_reportData == null) {
      return Center(
        child: Text('Click Report to generate a full security assessment.',
            style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
      );
    }

    if (_reportData!.containsKey('error')) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline,
                  size: 36, color: theme.colorScheme.error),
              const SizedBox(height: 8),
              Text('Report generation failed',
                  style: theme.textTheme.titleMedium),
              const SizedBox(height: 4),
              SelectableText(_reportData!['error'].toString(),
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.error)),
            ],
          ),
        ),
      );
    }

    final score = (_reportData!['overall_score'] as num?)?.toDouble() ?? 0;
    final riskLevel = _reportData!['risk_level']?.toString() ?? 'unknown';
    final sections =
        (_reportData!['sections'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final stats = _reportData!['statistics'] as Map<String, dynamic>? ?? {};

    Color riskColor() {
      switch (riskLevel) {
        case 'critical':
          return Colors.red.shade700;
        case 'high':
          return Colors.red;
        case 'medium':
          return Colors.orange;
        case 'low':
          return Colors.green;
        default:
          return Colors.grey;
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
                    style: TextStyle(
                        fontSize: 11,
                        color: riskColor(),
                        fontWeight: FontWeight.w600)),
              ),
              const Spacer(),
              IconButton(
                icon: _evidencePackageRunning
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.inventory_2, size: 16),
                tooltip: 'Copy evidence package',
                onPressed: _evidencePackageRunning
                    ? null
                    : () async {
                        final apk = ref.read(apkProvider).selected;
                        if (apk?.id == null) return;
                        setState(() => _evidencePackageRunning = true);
                        try {
                          final api = ref.read(apiServiceProvider);
                          final pkg = await api.evidencePackage(apk!.id!);
                          final md = (pkg['markdown'] ?? '').toString();
                          Clipboard.setData(ClipboardData(text: md));
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                  content: Text('Evidence package copied'),
                                  duration: Duration(seconds: 1)),
                            );
                          }
                        } catch (e) {
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text('Export failed: $e')),
                            );
                          }
                        } finally {
                          if (mounted) {
                            setState(() => _evidencePackageRunning = false);
                          }
                        }
                      },
              ),
              IconButton(
                icon: const Icon(Icons.copy, size: 16),
                tooltip: 'Copy report',
                onPressed: () {
                  final text = _formatReportText();
                  Clipboard.setData(ClipboardData(text: text));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                        content: Text('Report copied'),
                        duration: Duration(seconds: 1)),
                  );
                },
              ),
              IconButton(
                icon: const Icon(Icons.refresh, size: 16),
                tooltip: 'Regenerate',
                onPressed: () {
                  final state = ref.read(apkProvider);
                  if (state.selected != null) _generateReport(state.selected!);
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
              _statChip(
                  'Permissions', '${stats['total_permissions'] ?? 0}', theme),
              _statChip(
                  'Dangerous', '${stats['dangerous_permissions'] ?? 0}', theme,
                  color: Colors.orange),
              _statChip(
                  'Exported', '${stats['exported_components'] ?? 0}', theme),
              _statChip('Secrets', '${stats['secrets_found'] ?? 0}', theme,
                  color: Colors.red),
              _statChip('APIs', '${stats['dangerous_apis'] ?? 0}', theme,
                  color: Colors.orange),
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
                  case 'pass':
                    return Colors.green;
                  case 'warn':
                    return Colors.orange;
                  case 'fail':
                    return Colors.red;
                  default:
                    return Colors.grey;
                }
              }

              IconData statusIcon() {
                switch (status) {
                  case 'pass':
                    return Icons.check_circle;
                  case 'warn':
                    return Icons.warning_amber;
                  case 'fail':
                    return Icons.cancel;
                  default:
                    return Icons.info_outline;
                }
              }

              return Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Container(
                  decoration: BoxDecoration(
                    border: Border(
                        left: BorderSide(color: statusColor(), width: 3)),
                    color: theme.colorScheme.surfaceContainerHighest
                        .withValues(alpha: 0.3),
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
                                style: theme.textTheme.bodyMedium
                                    ?.copyWith(fontWeight: FontWeight.w600)),
                          ),
                          Text(category,
                              style: TextStyle(
                                  fontSize: 10, color: Colors.grey.shade600)),
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
                                      fontFamily: 'monospace',
                                      fontSize: 11,
                                      color: Colors.grey.shade700)),
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

  Widget _statChip(String label, String value, ThemeData theme,
      {Color? color}) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text('$label: ',
            style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
        Text(value,
            style: TextStyle(
                fontSize: 12, fontWeight: FontWeight.w600, color: color)),
      ],
    );
  }

  String _formatReportText() {
    if (_reportData == null) return '';
    final score = (_reportData!['overall_score'] as num?)?.toDouble() ?? 0;
    final riskLevel = _reportData!['risk_level']?.toString() ?? 'unknown';
    final sections =
        (_reportData!['sections'] as List?)?.cast<Map<String, dynamic>>() ?? [];
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

  // ===== Hooks Generation =====

  Future<void> _generateHooks(ApkInfo apk) async {
    if (apk.id == null) {
      setState(() {
        _hooksData = [
          {'error': 'APK has no ID'}
        ];
      });
      return;
    }
    setState(() {
      _hooksRunning = true;
      _hooksData = null;
      if (_fridaTargetController.text.trim().isEmpty &&
          apk.packageName.isNotEmpty) {
        _fridaTargetController.text = apk.packageName;
      }
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.generateHooks(apk.id!);
      final hooks = (res['hooks'] as List?)?.cast<Map<String, dynamic>>() ?? [];
      setState(() {
        _hooksData = hooks;
        _hooksRunning = false;
      });
    } catch (e) {
      setState(() {
        _hooksData = [
          {'error': e.toString()}
        ];
        _hooksRunning = false;
      });
    }
  }

  Widget _buildHooksView(ThemeData theme) {
    if (_hooksRunning) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 12),
            Text(
                'Generating Frida hooks from analysis and Entry Trace flows...'),
          ],
        ),
      );
    }

    if (_hooksData == null || _hooksData!.isEmpty) {
      return Center(
        child: Text(
            'Click Hooks to auto-generate Frida scripts from anti-detect, crypto, Firebase, and Entry Trace source→sink flows.',
            style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
      );
    }

    if (_hooksData!.length == 1 && _hooksData!.first.containsKey('error')) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline,
                  size: 36, color: theme.colorScheme.error),
              const SizedBox(height: 8),
              SelectableText(_hooksData!.first['error'].toString(),
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.error)),
            ],
          ),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Text('Generated Hooks (${_hooksData!.length})',
                  style: theme.textTheme.titleMedium),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.copy_all, size: 16),
                tooltip: 'Copy all hooks',
                onPressed: () {
                  final all = _hooksData!
                      .map((h) => '// ${h['name']}\n${h['code'] ?? ''}')
                      .join('\n\n');
                  Clipboard.setData(ClipboardData(text: all));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                        content: Text('All hooks copied'),
                        duration: Duration(seconds: 1)),
                  );
                },
              ),
              IconButton(
                icon: const Icon(Icons.refresh, size: 16),
                tooltip: 'Regenerate',
                onPressed: () {
                  final state = ref.read(apkProvider);
                  if (state.selected != null) _generateHooks(state.selected!);
                },
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Padding(
          padding: const EdgeInsets.all(12),
          child: _buildGeneratedHookRunControls(theme),
        ),
        const Divider(height: 1),
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.all(12),
            itemCount: _hooksData!.length,
            itemBuilder: (ctx, i) {
              final hook = _hooksData![i];
              final name = hook['name']?.toString() ?? 'Hook ${i + 1}';
              final category = hook['category']?.toString() ?? '';
              final description = hook['description']?.toString() ?? '';
              final code = hook['code']?.toString() ?? '';
              final reason = hook['reason']?.toString() ?? '';

              return Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Container(
                  decoration: BoxDecoration(
                    border: Border(
                        left: BorderSide(
                            color: theme.colorScheme.primary, width: 3)),
                    color: theme.colorScheme.surfaceContainerHighest
                        .withValues(alpha: 0.3),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Theme(
                    data: theme.copyWith(dividerColor: Colors.transparent),
                    child: ExpansionTile(
                      tilePadding: const EdgeInsets.symmetric(horizontal: 12),
                      childrenPadding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
                      title: Row(
                        children: [
                          Expanded(
                            child: Text(name,
                                style: theme.textTheme.bodyMedium
                                    ?.copyWith(fontWeight: FontWeight.w600)),
                          ),
                          if (category.isNotEmpty)
                            Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 6, vertical: 1),
                              decoration: BoxDecoration(
                                color: theme.colorScheme.primary
                                    .withValues(alpha: 0.1),
                                borderRadius: BorderRadius.circular(3),
                              ),
                              child: Text(category,
                                  style: const TextStyle(fontSize: 10)),
                            ),
                        ],
                      ),
                      subtitle: description.isNotEmpty
                          ? Text(description,
                              style: theme.textTheme.bodySmall
                                  ?.copyWith(color: Colors.grey))
                          : null,
                      children: [
                        if (reason.isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.only(bottom: 8),
                            child: Text('Reason: $reason',
                                style: theme.textTheme.bodySmall?.copyWith(
                                    fontStyle: FontStyle.italic,
                                    color: Colors.grey)),
                          ),
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: theme.colorScheme.surface,
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: theme.dividerColor),
                          ),
                          child: Stack(
                            children: [
                              SelectableText(code,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                      fontFamily: 'monospace', fontSize: 11)),
                              Positioned(
                                top: 0,
                                right: 0,
                                child: Row(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    IconButton(
                                      icon: const Icon(Icons.play_arrow,
                                          size: 14),
                                      tooltip: 'Run generated hook',
                                      onPressed: _fridaRunning || code.isEmpty
                                          ? null
                                          : () => _runGeneratedHook(hook),
                                      visualDensity: VisualDensity.compact,
                                      padding: EdgeInsets.zero,
                                      constraints: const BoxConstraints(
                                          minWidth: 24, minHeight: 24),
                                    ),
                                    IconButton(
                                      icon: const Icon(Icons.copy, size: 14),
                                      tooltip: 'Copy',
                                      onPressed: () {
                                        Clipboard.setData(
                                            ClipboardData(text: code));
                                        ScaffoldMessenger.of(context)
                                            .showSnackBar(
                                          const SnackBar(
                                              content: Text('Hook copied'),
                                              duration: Duration(seconds: 1)),
                                        );
                                      },
                                      visualDensity: VisualDensity.compact,
                                      padding: EdgeInsets.zero,
                                      constraints: const BoxConstraints(
                                          minWidth: 24, minHeight: 24),
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildGeneratedHookRunControls(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Icon(Icons.play_circle_outline,
                size: 16, color: theme.colorScheme.primary),
            const SizedBox(width: 6),
            Expanded(
              child: Text(
                'Run generated hook with Frida',
                style: theme.textTheme.labelMedium
                    ?.copyWith(fontWeight: FontWeight.w600),
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: TextField(
                controller: _fridaSerialController,
                decoration: const InputDecoration(
                  labelText: 'Device serial',
                  hintText: 'emulator-5554',
                  isDense: true,
                  contentPadding:
                      EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                  border: OutlineInputBorder(),
                ),
                style: const TextStyle(fontSize: 12),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: TextField(
                controller: _fridaTargetController,
                decoration: const InputDecoration(
                  labelText: 'Target package',
                  hintText: 'com.example.app',
                  isDense: true,
                  contentPadding:
                      EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                  border: OutlineInputBorder(),
                ),
                style: const TextStyle(fontSize: 12),
              ),
            ),
          ],
        ),
        if (_fridaEvidenceData != null) ...[
          const SizedBox(height: 8),
          _buildRuntimeEvidenceSummary(theme),
        ],
        if (_fridaEvidenceData != null) ...[
          const SizedBox(height: 8),
          _buildRuntimeEvidenceSummary(theme),
        ],
        if (_fridaRunOutput != null) ...[
          const SizedBox(height: 8),
          Container(
            constraints: const BoxConstraints(maxHeight: 120),
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              borderRadius: BorderRadius.circular(4),
              border: Border.all(
                color: _fridaRunOutput!.startsWith('Error')
                    ? theme.colorScheme.error.withValues(alpha: 0.5)
                    : theme.colorScheme.primary.withValues(alpha: 0.3),
              ),
            ),
            child: SingleChildScrollView(
              child: SelectableText(
                _fridaRunOutput!,
                style: TextStyle(
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: _fridaRunOutput!.startsWith('Error')
                      ? theme.colorScheme.error
                      : null,
                ),
              ),
            ),
          ),
        ],
      ],
    );
  }

  Future<void> _runGeneratedHook(Map<String, dynamic> hook) async {
    final serial = _fridaSerialController.text.trim();
    final target = _fridaTargetController.text.trim();
    final code = hook['code']?.toString() ?? '';
    final name = hook['name']?.toString() ?? hook['id']?.toString() ?? 'hook';
    final hookId = hook['id']?.toString();
    final apkId = ref.read(apkProvider).selected?.id;
    if (serial.isEmpty || target.isEmpty) {
      setState(() => _fridaRunOutput =
          'Error: device serial and target package are required');
      return;
    }
    if (code.isEmpty) {
      setState(() => _fridaRunOutput = 'Error: generated hook code is empty');
      return;
    }
    setState(() {
      _fridaRunning = true;
      _fridaRunOutput = 'Running generated hook: $name ...';
      _fridaEvidenceData = null;
      _fridaEvidencePersisted = false;
      _fridaEvidencePersistError = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.runFridaCode(serial, target, code,
          apkId: apkId, hookId: hookId);
      final output = res['output']?.toString() ?? '';
      final error = res['error']?.toString();
      final evidence = _asStringMap(res['evidence']);
      setState(() {
        _fridaRunning = false;
        _fridaEvidenceData = evidence.isEmpty ? null : evidence;
        _fridaEvidencePersisted = res['evidence_persisted'] == true;
        _fridaEvidencePersistError = res['evidence_persist_error']?.toString();
        _fridaRunOutput = error != null
            ? 'Error: $error\n$output'
            : output.isEmpty
                ? '(no output)'
                : output;
      });
    } catch (e) {
      setState(() {
        _fridaRunning = false;
        _fridaEvidenceData = null;
        _fridaEvidencePersisted = false;
        _fridaEvidencePersistError = null;
        _fridaRunOutput = 'Error: $e';
      });
    }
  }

  Widget _buildRuntimeEvidenceSummary(ThemeData theme) {
    final evidence = _fridaEvidenceData;
    if (evidence == null || evidence.isEmpty) {
      return const SizedBox.shrink();
    }
    final summary = _asStringMap(evidence['summary']);
    final events = _asMapList(evidence['events']);
    final total = _num(summary['total']);
    final entryTrace = _num(summary['entry_trace']);
    final byKind = _asStringMap(summary['by_kind']);
    final correlated = _correlateRuntimeEvidence(events);
    final color = total > 0 ? Colors.green : Colors.orange;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.32)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(total > 0 ? Icons.fact_check : Icons.info_outline,
                  size: 16, color: color),
              const SizedBox(width: 6),
              Text(
                total > 0
                    ? 'Runtime evidence: $entryTrace ENTRY_TRACE hit(s)'
                    : 'Runtime evidence: no ENTRY_TRACE hits parsed yet',
                style: theme.textTheme.labelMedium
                    ?.copyWith(fontWeight: FontWeight.w600, color: color),
              ),
              const Spacer(),
              if (byKind.isNotEmpty)
                Text(
                  byKind.entries.map((e) => '${e.key}:${e.value}').join('  '),
                  style: theme.textTheme.bodySmall
                      ?.copyWith(fontFamily: 'monospace'),
                ),
            ],
          ),
          if (_fridaEvidencePersisted || _fridaEvidencePersistError != null)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                _fridaEvidencePersisted
                    ? 'Saved to APK runtime_evidence analysis.'
                    : 'Persist warning: $_fridaEvidencePersistError',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: _fridaEvidencePersisted ? Colors.green : Colors.orange,
                ),
              ),
            ),
          if (events.isNotEmpty) ...[
            const SizedBox(height: 6),
            ...events.take(5).map((e) {
              final op = (e['operation'] ?? e['kind'] ?? 'event').toString();
              final value = (e['value'] ?? e['raw'] ?? '').toString();
              return Padding(
                padding: const EdgeInsets.only(top: 3),
                child: SelectableText(
                  '• [${e['kind'] ?? ''}] $op${value.isEmpty ? '' : ': $value'}',
                  style: theme.textTheme.bodySmall
                      ?.copyWith(fontFamily: 'monospace', fontSize: 11),
                ),
              );
            }),
          ],
          if (correlated.isNotEmpty) ...[
            const SizedBox(height: 6),
            Text(
              correlated.any((m) => m['match'] == 'exact')
                  ? 'Exact flow correlation'
                  : 'Candidate flow correlation',
              style: theme.textTheme.bodySmall
                  ?.copyWith(fontWeight: FontWeight.w600),
            ),
            ...correlated.take(5).map((m) {
              final flow = _asStringMap(m['flow']);
              final event = _asStringMap(m['event']);
              final sink = _asStringMap(flow['sink']);
              return Padding(
                padding: const EdgeInsets.only(top: 3),
                child: SelectableText(
                  '• ${m['match'] == 'exact' ? 'exact' : 'candidate'} ${flow['flow_id'] ?? 'flow'} [${event['kind'] ?? ''}] ${flow['component'] ?? ''} → ${sink['kind'] ?? ''}:${sink['pattern'] ?? ''}',
                  style: theme.textTheme.bodySmall
                      ?.copyWith(fontFamily: 'monospace', fontSize: 11),
                ),
              );
            }),
          ],
        ],
      ),
    );
  }

  List<Map<String, dynamic>> _correlateRuntimeEvidence(
      List<Map<String, dynamic>> events) {
    final plan = _runtimePlanData;
    if (plan == null || events.isEmpty) {
      return const [];
    }
    final flows = _asMapList(plan['flows']);
    if (flows.isEmpty) {
      return const [];
    }
    final flowsByID = <String, Map<String, dynamic>>{};
    for (final flow in flows) {
      final flowID = (flow['flow_id'] ?? '').toString();
      if (flowID.isNotEmpty) {
        flowsByID[flowID] = flow;
      }
    }
    final out = <Map<String, dynamic>>[];
    final seen = <String>{};
    for (final event in events) {
      final eventKind = (event['kind'] ?? '').toString();
      if (eventKind.isEmpty) continue;
      final eventFlowIDs = _asStringList(event['flow_ids']);
      if (eventFlowIDs.isNotEmpty) {
        for (final flowID in eventFlowIDs) {
          final flow = flowsByID[flowID];
          if (flow == null) continue;
          final key = 'exact:${event['line']}:$flowID';
          if (!seen.add(key)) continue;
          out.add({'event': event, 'flow': flow, 'match': 'exact'});
        }
        continue;
      }
      for (final flow in flows) {
        final sink = _asStringMap(flow['sink']);
        final sinkKind = (sink['kind'] ?? '').toString();
        if (!_runtimeEvidenceMatchesSink(eventKind, sinkKind)) continue;
        final key = 'candidate:${event['line']}:${flow['flow_id'] ?? sinkKind}';
        if (!seen.add(key)) continue;
        out.add({'event': event, 'flow': flow, 'match': 'candidate'});
      }
    }
    return out;
  }

  bool _runtimeEvidenceMatchesSink(String eventKind, String sinkKind) {
    switch (eventKind) {
      case 'exec':
        return sinkKind == 'command_exec' || sinkKind == 'smali_command_exec';
      case 'webview':
        return sinkKind == 'webview' ||
            sinkKind == 'smali_webview' ||
            sinkKind == 'webview_bridge';
      case 'intent':
        return sinkKind == 'activity_launch' ||
            sinkKind == 'smali_activity_launch' ||
            sinkKind == 'service_launch' ||
            sinkKind == 'broadcast';
      case 'sqlite':
        return sinkKind == 'sqlite' || sinkKind == 'smali_sqlite';
      case 'network':
        return sinkKind == 'network';
      case 'file':
        return sinkKind == 'file_write';
      default:
        return eventKind == sinkKind;
    }
  }

  // ===== Runtime Plan =====

  Future<void> _generateRuntimePlan(ApkInfo apk) async {
    if (apk.id == null) {
      setState(() => _runtimePlanData = {'error': 'APK has no ID'});
      return;
    }
    setState(() {
      _runtimePlanRunning = true;
      _runtimePlanData = null;
      if (_fridaTargetController.text.trim().isEmpty &&
          apk.packageName.isNotEmpty) {
        _fridaTargetController.text = apk.packageName;
      }
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.runtimePlan(
        apk.id!,
        serial: _fridaSerialController.text.trim(),
      );
      final target = _asStringMap(res['target']);
      final pkg = (target['package'] ?? '').toString();
      if (pkg.isNotEmpty && _fridaTargetController.text.trim().isEmpty) {
        _fridaTargetController.text = pkg;
      }
      setState(() {
        _runtimePlanData = res;
        _runtimePlanRunning = false;
      });
    } catch (e) {
      setState(() {
        _runtimePlanData = {'error': e.toString()};
        _runtimePlanRunning = false;
      });
    }
  }

  Widget _buildRuntimePlanView(ThemeData theme) {
    if (_runtimePlanRunning) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 12),
            Text('Building runtime validation plan...'),
          ],
        ),
      );
    }

    if (_runtimePlanData == null) {
      return Center(
        child: Text(
          'Click Runtime Plan to combine Entry Trace flows, ADB replay commands, generated Frida hooks, and validation steps without touching a device.',
          style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey),
          textAlign: TextAlign.center,
        ),
      );
    }

    if (_runtimePlanData!.containsKey('error')) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline,
                  size: 36, color: theme.colorScheme.error),
              const SizedBox(height: 8),
              SelectableText(_runtimePlanData!['error'].toString(),
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.error)),
            ],
          ),
        ),
      );
    }

    final data = _runtimePlanData!;
    final target = _asStringMap(data['target']);
    final entryTrace = _asStringMap(data['entry_trace']);
    final summary = _asStringMap(entryTrace['summary']);
    final flows = _asMapList(data['flows']);
    final replay = _asStringList(data['adb_replay']);
    final hooks = _asMapList(data['generated_hooks']);
    final steps = _asStringList(data['validation_steps']);
    final ready = target['ready_to_run'] == true;

    Widget commandLine(String command) {
      return Container(
        width: double.infinity,
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color:
              theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: SelectableText(command,
                  style: theme.textTheme.bodySmall
                      ?.copyWith(fontFamily: 'monospace', fontSize: 11)),
            ),
            IconButton(
              icon: const Icon(Icons.copy, size: 14),
              tooltip: 'Copy command',
              visualDensity: VisualDensity.compact,
              onPressed: () {
                Clipboard.setData(ClipboardData(text: command));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                      content: Text('Command copied'),
                      duration: Duration(seconds: 1)),
                );
              },
            ),
          ],
        ),
      );
    }

    Widget flowLine(Map<String, dynamic> flow) {
      final source = _asStringMap(flow['source']);
      final sink = _asStringMap(flow['sink']);
      final variables = _asStringList(flow['variables']);
      final risk = (flow['risk'] ?? '').toString();
      final detail = [
        '${flow['file'] ?? ''}:${source['line'] ?? ''} → ${sink['line'] ?? ''}',
        if (variables.isNotEmpty) 'via ${variables.join(', ')}',
        (flow['reason'] ?? '').toString(),
      ].where((v) => v.trim().isNotEmpty && v != ': → ').join('  ');
      return _triageFindingLine(
        '${flow['flow_id'] ?? 'flow'} / ${flow['component'] ?? ''} / ${source['kind'] ?? 'source'}:${source['pattern'] ?? ''} → ${sink['kind'] ?? 'sink'}:${sink['pattern'] ?? ''}',
        detail,
        theme,
        tag: risk.toUpperCase(),
        danger: risk == 'high',
      );
    }

    Widget hookLine(Map<String, dynamic> hook) {
      final args = _asStringMap(hook['frida_hook_args']);
      final code = (hook['code'] ?? args['script'] ?? '').toString();
      return Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: _triageFindingLine(
                (hook['name'] ?? hook['id'] ?? 'hook').toString(),
                (hook['reason'] ?? hook['description'] ?? '').toString(),
                theme,
                tag: (hook['category'] ?? '').toString(),
              ),
            ),
            IconButton(
              icon: const Icon(Icons.play_arrow, size: 16),
              tooltip: 'Run this hook',
              visualDensity: VisualDensity.compact,
              onPressed: _fridaRunning || code.isEmpty
                  ? null
                  : () => _runGeneratedHook({...hook, 'code': code}),
            ),
            IconButton(
              icon: const Icon(Icons.copy, size: 16),
              tooltip: 'Copy hook code',
              visualDensity: VisualDensity.compact,
              onPressed: code.isEmpty
                  ? null
                  : () {
                      Clipboard.setData(ClipboardData(text: code));
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                            content: Text('Hook copied'),
                            duration: Duration(seconds: 1)),
                      );
                    },
            ),
          ],
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Text('Runtime Validation Plan',
                  style: theme.textTheme.titleMedium),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.copy_all, size: 16),
                tooltip: 'Copy plan JSON',
                onPressed: () {
                  Clipboard.setData(ClipboardData(
                      text: const JsonEncoder.withIndent('  ').convert(data)));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                        content: Text('Runtime plan copied'),
                        duration: Duration(seconds: 1)),
                  );
                },
              ),
              IconButton(
                icon: const Icon(Icons.refresh, size: 16),
                tooltip: 'Regenerate',
                onPressed: () {
                  final state = ref.read(apkProvider);
                  if (state.selected != null) {
                    _generateRuntimePlan(state.selected!);
                  }
                },
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Padding(
          padding: const EdgeInsets.all(12),
          child: _buildGeneratedHookRunControls(theme),
        ),
        const Divider(height: 1),
        Expanded(
          child: ListView(
            padding: const EdgeInsets.all(12),
            children: [
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  _triageMetric('Ready', ready ? 'yes' : 'no',
                      ready ? Icons.check_circle : Icons.info_outline, theme,
                      danger: !ready),
                  _triageMetric('Flows', flows.length.toString(),
                      Icons.account_tree, theme,
                      danger: flows.isNotEmpty),
                  _triageMetric('Replay', replay.length.toString(),
                      Icons.terminal, theme),
                  _triageMetric('Hooks', hooks.length.toString(),
                      Icons.auto_fix_high, theme),
                  _triageMetric(
                      'Trace risk',
                      (summary['risk_level'] ?? 'unknown').toString(),
                      Icons.speed,
                      theme,
                      danger: summary['risk_level'] == 'high'),
                ],
              ),
              const SizedBox(height: 12),
              _triageCard(
                'Target',
                Icons.track_changes,
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _kv(
                        'serial',
                        (target['serial'] ?? '(choose a device)').toString(),
                        theme,
                        mono: true),
                    _kv('package', (target['package'] ?? '').toString(), theme,
                        mono: true),
                    _kv('boundary',
                        (data['execution_boundary'] ?? '').toString(), theme),
                  ],
                ),
                theme,
                accent: ready ? Colors.green : Colors.orange,
              ),
              const SizedBox(height: 12),
              _triageFindingsSection(
                  'Validation steps',
                  steps
                      .asMap()
                      .entries
                      .map((e) => _triageFindingLine(
                          'Step ${e.key + 1}', e.value, theme))
                      .toList(),
                  theme),
              _triageFindingsSection('Source → sink flows',
                  flows.take(20).map(flowLine).toList(), theme),
              if (replay.isNotEmpty)
                _triageCard(
                  'ADB replay commands',
                  Icons.terminal,
                  Column(children: replay.take(20).map(commandLine).toList()),
                  theme,
                ),
              if (hooks.isNotEmpty) ...[
                const SizedBox(height: 12),
                _triageCard(
                  'Generated Frida hooks',
                  Icons.auto_fix_high,
                  Column(children: hooks.take(10).map(hookLine).toList()),
                  theme,
                ),
              ],
              const SizedBox(height: 12),
              _expandable(
                'Raw runtime_plan JSON',
                [
                  SelectableText(
                    const JsonEncoder.withIndent('  ').convert(data),
                    style: theme.textTheme.bodySmall
                        ?.copyWith(fontFamily: 'monospace', fontSize: 11),
                  ),
                ],
                theme,
              ),
            ],
          ),
        ),
      ],
    );
  }

  // ===== Call Graph =====

  Future<void> _loadCallGraph(ApkInfo apk) async {
    if (apk.id == null) {
      setState(() {
        _callgraphData = {'error': 'APK has no ID'};
      });
      return;
    }
    setState(() {
      _callgraphRunning = true;
      _callgraphData = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.callGraph(apk.id!);
      setState(() {
        _callgraphData = res;
        _callgraphRunning = false;
      });
    } catch (e) {
      setState(() {
        _callgraphData = {'error': e.toString()};
        _callgraphRunning = false;
      });
    }
  }

  Widget _buildCallGraphView(ThemeData theme) {
    if (_callgraphRunning) {
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

    if (_callgraphData == null) {
      return Center(
        child: Text('Click Call Graph to analyze method call relationships.',
            style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
      );
    }

    if (_callgraphData!.containsKey('error')) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline,
                  size: 36, color: theme.colorScheme.error),
              const SizedBox(height: 8),
              SelectableText(_callgraphData!['error'].toString(),
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.error)),
            ],
          ),
        ),
      );
    }

    final stats = _callgraphData!['stats'] as Map<String, dynamic>? ?? {};
    final hotMethods = (_callgraphData!['hot_methods'] as List?)
            ?.cast<Map<String, dynamic>>() ??
        [];
    final paths =
        (_callgraphData!['paths'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final entryPoints =
        (_callgraphData!['entry_points'] as List?)?.cast<String>() ?? [];
    final nodes = (_callgraphData!['nodes'] as List?)?.length ?? 0;
    final edges = (_callgraphData!['edges'] as List?)?.length ?? 0;

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
                  final state = ref.read(apkProvider);
                  if (state.selected != null) _loadCallGraph(state.selected!);
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
                  Text('Data Flow Paths (source → sink)',
                      style: theme.textTheme.labelLarge),
                  const SizedBox(height: 8),
                  ...paths.take(20).map((p) {
                    final risk = (p['risk'] ?? 'low').toString();
                    Color riskColor = Colors.green;
                    if (risk == 'high') riskColor = Colors.red;
                    if (risk == 'medium') riskColor = Colors.orange;
                    final pathSteps =
                        (p['path'] as List?)?.cast<String>() ?? [];
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          border: Border(
                              left: BorderSide(color: riskColor, width: 3)),
                          color: theme.colorScheme.surfaceContainerHighest
                              .withValues(alpha: 0.3),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                Container(
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 5, vertical: 1),
                                  decoration: BoxDecoration(
                                    color: riskColor.withValues(alpha: 0.15),
                                    borderRadius: BorderRadius.circular(3),
                                  ),
                                  child: Text(risk.toUpperCase(),
                                      style: TextStyle(
                                          fontSize: 9,
                                          color: riskColor,
                                          fontWeight: FontWeight.bold)),
                                ),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: Text('${p['source']} → ${p['sink']}',
                                      style: theme.textTheme.bodySmall
                                          ?.copyWith(
                                              fontWeight: FontWeight.w600)),
                                ),
                              ],
                            ),
                            if (pathSteps.isNotEmpty) ...[
                              const SizedBox(height: 6),
                              ...pathSteps.map((step) => Padding(
                                    padding:
                                        const EdgeInsets.only(left: 12, top: 2),
                                    child: Row(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Text('→ ',
                                            style: TextStyle(
                                                fontSize: 10,
                                                color: Colors.grey.shade600)),
                                        Expanded(
                                          child: SelectableText(step,
                                              style: theme.textTheme.bodySmall
                                                  ?.copyWith(
                                                      fontFamily: 'monospace',
                                                      fontSize: 10)),
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
                  Text('Hot Methods (high connectivity)',
                      style: theme.textTheme.labelLarge),
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
                              style: const TextStyle(
                                  fontSize: 10, fontFamily: 'monospace')),
                          visualDensity: VisualDensity.compact,
                          materialTapTargetSize:
                              MaterialTapTargetSize.shrinkWrap,
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
                            style: theme.textTheme.bodySmall?.copyWith(
                                fontFamily: 'monospace', fontSize: 11)),
                      )),
                ],
              ],
            ),
          ),
        ),
      ],
    );
  }

  // ===== APK Diff =====

  Widget _buildDiffView(ApkState state, ThemeData theme) {
    final currentApk = state.selected!;
    final otherApks =
        state.apks.where((a) => a.path != currentApk.path).toList();

    if (otherApks.isEmpty) {
      return Center(
        child: Text('Upload at least 2 APKs to compare versions.',
            style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Text('Compare: ', style: theme.textTheme.bodySmall),
              const SizedBox(width: 8),
              Expanded(
                child: DropdownMenu<String>(
                  initialSelection: _diffTargetId,
                  expandedInsets: EdgeInsets.zero,
                  requestFocusOnTap: false,
                  label: const Text('Compare with...',
                      style: TextStyle(fontSize: 12)),
                  textStyle: const TextStyle(fontSize: 12),
                  inputDecorationTheme: const InputDecorationTheme(
                    border: OutlineInputBorder(),
                    isDense: true,
                    contentPadding:
                        EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  ),
                  dropdownMenuEntries: otherApks
                      .map((a) => DropdownMenuEntry(
                            value: a.id ?? '',
                            label: a.packageName.isEmpty
                                ? a.path.split('/').last
                                : '${a.packageName} v${a.versionName}',
                          ))
                      .toList(),
                  onSelected: (v) => setState(() => _diffTargetId = v),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                onPressed: (_diffRunning ||
                        _diffTargetId == null ||
                        (currentApk.id ?? '').isEmpty)
                    ? null
                    : () => _runDiff(currentApk.id!, _diffTargetId!),
                icon: _diffRunning
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.compare_arrows, size: 16),
                label: Text(_diffRunning ? 'Comparing...' : 'Compare'),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: _diffData == null
              ? Center(
                  child: Text('Select another APK version and click Compare.',
                      style: theme.textTheme.bodySmall
                          ?.copyWith(color: Colors.grey)),
                )
              : _diffData!.containsKey('error')
                  ? Center(
                      child: SelectableText(_diffData!['error'].toString(),
                          style: theme.textTheme.bodySmall
                              ?.copyWith(color: theme.colorScheme.error)),
                    )
                  : SingleChildScrollView(
                      padding: const EdgeInsets.all(16),
                      child: _renderDiffResult(_diffData!, theme),
                    ),
        ),
      ],
    );
  }

  Future<void> _runDiff(String oldId, String newId) async {
    setState(() {
      _diffRunning = true;
      _diffData = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.diffAPKs(oldId, newId);
      setState(() {
        _diffData = res;
        _diffRunning = false;
      });
    } catch (e) {
      setState(() {
        _diffData = {'error': e.toString()};
        _diffRunning = false;
      });
    }
  }

  Widget _renderDiffResult(Map<String, dynamic> data, ThemeData theme) {
    final summary = data['summary'] as Map<String, dynamic>? ?? {};
    final riskDelta = (summary['risk_delta'] as num?)?.toInt() ?? 0;

    Widget diffSection(
        String title, IconData icon, List? added, List? removed) {
      final addedList = (added ?? []).cast<String>();
      final removedList = (removed ?? []).cast<String>();
      if (addedList.isEmpty && removedList.isEmpty) {
        return const SizedBox.shrink();
      }
      return Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, size: 14),
                const SizedBox(width: 6),
                Text(title, style: theme.textTheme.labelLarge),
                const SizedBox(width: 8),
                if (addedList.isNotEmpty)
                  Text('+${addedList.length}',
                      style: const TextStyle(
                          fontSize: 11,
                          color: Colors.green,
                          fontWeight: FontWeight.w600)),
                if (removedList.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(left: 6),
                    child: Text('-${removedList.length}',
                        style: TextStyle(
                            fontSize: 11,
                            color: theme.colorScheme.error,
                            fontWeight: FontWeight.w600)),
                  ),
              ],
            ),
            const SizedBox(height: 6),
            ...addedList.take(20).map((item) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 1),
                  child: Row(
                    children: [
                      const Text('+ ',
                          style: TextStyle(
                              color: Colors.green,
                              fontFamily: 'monospace',
                              fontSize: 11)),
                      Expanded(
                          child: SelectableText(item,
                              style: theme.textTheme.bodySmall?.copyWith(
                                  fontFamily: 'monospace', fontSize: 11))),
                    ],
                  ),
                )),
            ...removedList.take(20).map((item) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 1),
                  child: Row(
                    children: [
                      Text('- ',
                          style: TextStyle(
                              color: theme.colorScheme.error,
                              fontFamily: 'monospace',
                              fontSize: 11)),
                      Expanded(
                          child: SelectableText(item,
                              style: theme.textTheme.bodySmall?.copyWith(
                                  fontFamily: 'monospace', fontSize: 11))),
                    ],
                  ),
                )),
          ],
        ),
      );
    }

    final perms = data['permissions'] as Map<String, dynamic>? ?? {};
    final components = data['components'] as Map<String, dynamic>? ?? {};
    final files = data['files'] as Map<String, dynamic>? ?? {};
    final nativeLibs = data['native_libs'] as Map<String, dynamic>? ?? {};
    final sdks = data['sdks'] as Map<String, dynamic>? ?? {};

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text('Risk Delta: ', style: theme.textTheme.titleSmall),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                color: (riskDelta > 0
                        ? Colors.red
                        : riskDelta < 0
                            ? Colors.green
                            : Colors.grey)
                    .withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                riskDelta > 0 ? '+$riskDelta' : '$riskDelta',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: riskDelta > 0
                      ? Colors.red
                      : riskDelta < 0
                          ? Colors.green
                          : Colors.grey,
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        diffSection('Permissions', Icons.security, perms['added'] as List?,
            perms['removed'] as List?),
        diffSection('Components', Icons.widgets, components['added'] as List?,
            components['removed'] as List?),
        diffSection('Native Libraries', Icons.memory,
            nativeLibs['added'] as List?, nativeLibs['removed'] as List?),
        diffSection('SDKs', Icons.extension, sdks['added'] as List?,
            sdks['removed'] as List?),
        if (files['added'] != null ||
            files['removed'] != null ||
            files['changed'] != null) ...[
          Row(
            children: [
              const Icon(Icons.folder, size: 14),
              const SizedBox(width: 6),
              Text('Files', style: theme.textTheme.labelLarge),
              const SizedBox(width: 8),
              if ((files['added'] as List?)?.isNotEmpty ?? false)
                Text('+${(files['added'] as List).length}',
                    style: const TextStyle(
                        fontSize: 11,
                        color: Colors.green,
                        fontWeight: FontWeight.w600)),
              if ((files['removed'] as List?)?.isNotEmpty ?? false)
                Padding(
                  padding: const EdgeInsets.only(left: 6),
                  child: Text('-${(files['removed'] as List).length}',
                      style: TextStyle(
                          fontSize: 11,
                          color: theme.colorScheme.error,
                          fontWeight: FontWeight.w600)),
                ),
              if ((files['changed'] as List?)?.isNotEmpty ?? false)
                Padding(
                  padding: const EdgeInsets.only(left: 6),
                  child: Text('~${(files['changed'] as List).length}',
                      style: const TextStyle(
                          fontSize: 11,
                          color: Colors.orange,
                          fontWeight: FontWeight.w600)),
                ),
            ],
          ),
          const SizedBox(height: 6),
        ],
      ],
    );
  }

  // ===== Radare2 Tab =====

  Widget _buildRadare2Tab(ApkState state, ThemeData theme) {
    final apk = state.selected!;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _r2FileController,
                      decoration: InputDecoration(
                        labelText: 'File path (.so or DEX)',
                        hintText: 'lib/arm64-v8a/libnative.so',
                        border: const OutlineInputBorder(),
                        isDense: true,
                        contentPadding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 10),
                        suffixIcon: IconButton(
                          icon: const Icon(Icons.folder_open, size: 16),
                          tooltip: 'Use APK lib path',
                          onPressed: () {
                            final base = apk.decompiledPath ?? apk.path;
                            _r2FileController.text = '$base/lib/';
                          },
                        ),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 6,
                runSpacing: 6,
                children: [
                  _actionChip('Info', Icons.info_outline,
                      _r2Running ? null : () => _runR2('info')),
                  _actionChip('Symbols', Icons.list,
                      _r2Running ? null : () => _runR2('symbols')),
                  _actionChip('Imports', Icons.input,
                      _r2Running ? null : () => _runR2('imports')),
                  _actionChip('Strings', Icons.text_fields,
                      _r2Running ? null : () => _runR2('strings')),
                  _actionChip('Functions', Icons.functions,
                      _r2Running ? null : () => _runR2('functions')),
                ],
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: _ResultPanel(
              content: _r2Result,
              isRunning: _r2Running,
              isError: _r2Result?.startsWith('Error') ?? false,
              emptyHint: 'Analyze native .so binaries (via radare2)',
            ),
          ),
        ),
      ],
    );
  }

  Widget _actionChip(String label, IconData icon, VoidCallback? onPressed) {
    return ActionChip(
      avatar: Icon(icon, size: 14),
      label: Text(label, style: const TextStyle(fontSize: 12)),
      onPressed: onPressed,
      visualDensity: VisualDensity.compact,
      materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
    );
  }

  Future<void> _runR2(String action) async {
    final filePath = _r2FileController.text.trim();
    if (filePath.isEmpty) {
      setState(() => _r2Result = 'Error: file path is required');
      return;
    }
    setState(() {
      _r2Running = true;
      _r2Result = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final Map<String, String> cmdMap = {
        'info': 'iI',
        'symbols': 'is',
        'imports': 'ii',
        'strings': 'iz',
        'functions': 'afl',
      };
      final res =
          await api.shellCommand('r2 -q -c "${cmdMap[action]}" "$filePath"');
      setState(() {
        _r2Result = res['output']?.toString() ?? 'No output';
        _r2Running = false;
      });
    } catch (e) {
      setState(() {
        _r2Result = 'Error: $e';
        _r2Running = false;
      });
    }
  }

  // ===== Androguard Tab =====

  Widget _buildAndroguardTab(ApkState state, ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Wrap(
            spacing: 6,
            runSpacing: 6,
            children: [
              _actionChip(
                  'Permissions',
                  Icons.security,
                  _androguardRunning
                      ? null
                      : () => _runAndroguard('permissions')),
              _actionChip(
                  'Activities',
                  Icons.view_list,
                  _androguardRunning
                      ? null
                      : () => _runAndroguard('activities')),
              _actionChip('Services', Icons.miscellaneous_services,
                  _androguardRunning ? null : () => _runAndroguard('services')),
              _actionChip(
                  'Receivers',
                  Icons.broadcast_on_personal,
                  _androguardRunning
                      ? null
                      : () => _runAndroguard('receivers')),
              _actionChip(
                  'Providers',
                  Icons.storage,
                  _androguardRunning
                      ? null
                      : () => _runAndroguard('providers')),
              _actionChip('Manifest', Icons.description,
                  _androguardRunning ? null : () => _runAndroguard('manifest')),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: _ResultPanel(
              content: _androguardResult,
              isRunning: _androguardRunning,
              isError: _androguardResult?.startsWith('Error') ?? false,
              emptyHint:
                  'Inspect APK components: permissions, activities, services (via androguard)',
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _runAndroguard(String action) async {
    final apk = ref.read(apkProvider).selected!;
    setState(() {
      _androguardRunning = true;
      _androguardResult = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final Map<String, String> cmdMap = {
        'permissions': 'androguard permissions -i "${apk.path}"',
        'activities': 'androguard activities -i "${apk.path}"',
        'services': 'androguard services -i "${apk.path}"',
        'receivers': 'androguard receivers -i "${apk.path}"',
        'providers': 'androguard providers -i "${apk.path}"',
        'manifest': 'androaxml -i "${apk.path}"',
      };
      final res = await api.shellCommand(cmdMap[action]!);
      setState(() {
        _androguardResult = res['output']?.toString() ?? 'No output';
        _androguardRunning = false;
      });
    } catch (e) {
      setState(() {
        _androguardResult = 'Error: $e';
        _androguardRunning = false;
      });
    }
  }

  // ===== Network / Frida Tab =====

  String _networkSubTab = 'proxy'; // 'proxy', 'capture', or 'frida'
  bool _captureLoading = false;
  Map<String, dynamic>? _captureResult;

  Widget _buildMitmproxyTab(ApkState state, ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Row(
            children: [
              SegmentedButton<String>(
                segments: const [
                  ButtonSegment(
                      value: 'proxy',
                      label: Text('Proxy', style: TextStyle(fontSize: 12)),
                      icon: Icon(Icons.wifi_tethering, size: 14)),
                  ButtonSegment(
                      value: 'capture',
                      label: Text('Capture', style: TextStyle(fontSize: 12)),
                      icon: Icon(Icons.upload_file, size: 14)),
                  ButtonSegment(
                      value: 'frida',
                      label:
                          Text('Frida Scripts', style: TextStyle(fontSize: 12)),
                      icon: Icon(Icons.code, size: 14)),
                ],
                selected: {_networkSubTab},
                onSelectionChanged: (v) {
                  setState(() => _networkSubTab = v.first);
                  if (v.first == 'frida' &&
                      _fridaScripts == null &&
                      !_fridaLoading) {
                    _loadFridaScripts();
                  }
                },
                style: const ButtonStyle(
                  visualDensity: VisualDensity.compact,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: switch (_networkSubTab) {
            'proxy' => _buildProxyContent(theme),
            'capture' => _buildCaptureContent(theme),
            _ => _buildFridaScriptsContent(theme),
          },
        ),
      ],
    );
  }

  Widget _buildProxyContent(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              SizedBox(
                width: 100,
                child: TextField(
                  controller: _mitmportController,
                  decoration: const InputDecoration(
                    labelText: 'Port',
                    hintText: '8080',
                    border: OutlineInputBorder(),
                    isDense: true,
                    contentPadding:
                        EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  ),
                  keyboardType: TextInputType.number,
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                onPressed: _mitmRunning ? null : _startMitmproxy,
                icon: const Icon(Icons.play_arrow, size: 16),
                label: const Text('Start'),
              ),
              const SizedBox(width: 6),
              OutlinedButton.icon(
                onPressed: _mitmRunning ? _stopMitmproxy : null,
                icon: const Icon(Icons.stop, size: 16),
                label: const Text('Stop'),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: _mitmResult == null && !_mitmRunning
                ? _buildMitmInstructions(theme)
                : _ResultPanel(
                    content: _mitmResult,
                    isRunning: _mitmRunning && _mitmResult == null,
                    isError: _mitmResult?.startsWith('Error') ?? false,
                    emptyHint: 'Proxy output will appear here',
                  ),
          ),
        ),
      ],
    );
  }

  Widget _buildCaptureContent(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              FilledButton.tonalIcon(
                onPressed: _captureLoading ? null : _pickAndParseCapture,
                icon: _captureLoading
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2))
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
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: _captureResult == null
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.cloud_upload_outlined,
                          size: 48, color: Colors.grey[400]),
                      const SizedBox(height: 12),
                      Text(
                          'Upload a .har or mitmproxy text dump to analyze network traffic',
                          style: theme.textTheme.bodyMedium
                              ?.copyWith(color: Colors.grey)),
                      const SizedBox(height: 4),
                      Text(
                          'Supports HAR (Chrome/Firefox export) and mitmproxy flow dumps',
                          style: theme.textTheme.bodySmall?.copyWith(
                              color: Colors.grey[500], fontSize: 11)),
                    ],
                  ),
                )
              : _buildCaptureResultView(theme),
        ),
      ],
    );
  }

  Widget _buildCaptureResultView(ThemeData theme) {
    final data = _captureResult!;
    final summary = data['summary'] as Map<String, dynamic>? ?? {};
    final requests =
        (data['requests'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final domains =
        (data['domains'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final endpoints =
        (data['api_endpoints'] as List?)?.cast<Map<String, dynamic>>() ?? [];

    return DefaultTabController(
      length: 3,
      child: Column(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            color: theme.colorScheme.surfaceContainerHighest
                .withValues(alpha: 0.3),
            child: Row(
              children: [
                _CaptureChip(
                    label: '${summary['total_requests'] ?? 0} requests',
                    icon: Icons.http),
                const SizedBox(width: 8),
                _CaptureChip(
                    label: '${summary['unique_hosts'] ?? 0} hosts',
                    icon: Icons.dns),
                const SizedBox(width: 8),
                if (summary['has_https'] == true)
                  const _CaptureChip(
                      label: 'HTTPS', icon: Icons.lock, color: Colors.green),
                if (summary['has_http'] == true) ...[
                  const SizedBox(width: 8),
                  const _CaptureChip(
                      label: 'HTTP',
                      icon: Icons.lock_open,
                      color: Colors.orange),
                ],
              ],
            ),
          ),
          TabBar(
            isScrollable: true,
            tabAlignment: TabAlignment.start,
            labelStyle: const TextStyle(fontSize: 11),
            tabs: [
              Tab(text: 'Requests (${requests.length})'),
              Tab(text: 'Domains (${domains.length})'),
              Tab(text: 'Endpoints (${endpoints.length})'),
            ],
          ),
          Expanded(
            child: TabBarView(
              children: [
                _buildRequestsList(requests, theme),
                _buildDomainsList(domains, theme),
                _buildEndpointsList(endpoints, theme),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRequestsList(
      List<Map<String, dynamic>> requests, ThemeData theme) {
    if (requests.isEmpty) {
      return const Center(child: Text('No requests captured'));
    }
    return ListView.builder(
      padding: const EdgeInsets.all(4),
      itemCount: requests.length,
      itemBuilder: (ctx, i) {
        final req = requests[i];
        final method = req['method']?.toString() ?? 'GET';
        final urlStr = req['url']?.toString() ?? '';
        final category = req['category']?.toString() ?? '';
        final status = req['status_code'] as int? ?? 0;

        Color methodColor;
        switch (method) {
          case 'POST':
            methodColor = Colors.orange;
            break;
          case 'PUT':
          case 'PATCH':
            methodColor = Colors.blue;
            break;
          case 'DELETE':
            methodColor = Colors.red;
            break;
          default:
            methodColor = Colors.green;
        }

        return Padding(
          padding: const EdgeInsets.only(bottom: 2),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: theme.colorScheme.surfaceContainerHighest
                  .withValues(alpha: 0.2),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Row(
              children: [
                Container(
                  width: 48,
                  padding:
                      const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                  decoration: BoxDecoration(
                    color: methodColor.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(method,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                          fontSize: 9,
                          fontWeight: FontWeight.w700,
                          color: methodColor)),
                ),
                const SizedBox(width: 6),
                if (status > 0) ...[
                  Text('$status',
                      style: TextStyle(
                          fontSize: 10,
                          color: status >= 400 ? Colors.red : Colors.grey[600],
                          fontWeight: FontWeight.w600)),
                  const SizedBox(width: 6),
                ],
                Expanded(
                  child: Text(urlStr,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                          fontSize: 11, fontFamily: 'monospace')),
                ),
                if (category.isNotEmpty)
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                    decoration: BoxDecoration(
                      color: _categoryColor(category).withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Text(category,
                        style: TextStyle(
                            fontSize: 9, color: _categoryColor(category))),
                  ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildDomainsList(
      List<Map<String, dynamic>> domains, ThemeData theme) {
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
          title: Text(domain,
              style: const TextStyle(fontSize: 12, fontFamily: 'monospace')),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (category.isNotEmpty)
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                  margin: const EdgeInsets.only(right: 8),
                  decoration: BoxDecoration(
                    color: _categoryColor(category).withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(category,
                      style: TextStyle(
                          fontSize: 9, color: _categoryColor(category))),
                ),
              Text('$count',
                  style: theme.textTheme.labelSmall
                      ?.copyWith(fontWeight: FontWeight.w600)),
            ],
          ),
        );
      },
    );
  }

  Widget _buildEndpointsList(
      List<Map<String, dynamic>> endpoints, ThemeData theme) {
    if (endpoints.isEmpty) {
      return const Center(child: Text('No endpoints found'));
    }
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
          title: Row(
            children: [
              Container(
                width: 48,
                padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                decoration: BoxDecoration(
                  color: Colors.grey.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: Text(method,
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                        fontSize: 9, fontWeight: FontWeight.w700)),
              ),
              const SizedBox(width: 6),
              Expanded(
                child: Text('$host$path',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style:
                        const TextStyle(fontSize: 11, fontFamily: 'monospace')),
              ),
            ],
          ),
          trailing: Text('x$count',
              style: theme.textTheme.labelSmall
                  ?.copyWith(fontWeight: FontWeight.w600)),
        );
      },
    );
  }

  Color _categoryColor(String category) {
    switch (category) {
      case 'analytics':
        return Colors.purple;
      case 'ad':
        return Colors.red;
      case 'cloud':
        return Colors.blue;
      case 'cdn':
        return Colors.teal;
      case 'social':
        return Colors.indigo;
      case 'payment':
        return Colors.amber.shade800;
      default:
        return Colors.grey;
    }
  }

  Future<void> _pickAndParseCapture() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.any,
      withData: true,
    );
    if (result == null || result.files.isEmpty) return;
    final file = result.files.first;
    if (file.bytes == null) return;

    setState(() => _captureLoading = true);
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.parseNetworkCapture(file.bytes!, file.name);
      setState(() {
        _captureLoading = false;
        _captureResult = res;
      });
    } catch (e) {
      setState(() => _captureLoading = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Parse error: $e')),
        );
      }
    }
  }

  Widget _buildFridaScriptsContent(ThemeData theme) {
    if (_fridaLoading && _fridaScripts == null) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 12),
            Text('Loading Frida scripts...'),
          ],
        ),
      );
    }

    if (_fridaScripts == null || _fridaScripts!.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.code_off, size: 48, color: Colors.grey[400]),
            const SizedBox(height: 12),
            Text('No Frida scripts available',
                style:
                    theme.textTheme.bodyMedium?.copyWith(color: Colors.grey)),
            const SizedBox(height: 8),
            FilledButton.tonalIcon(
              onPressed: _fridaLoading ? null : _loadFridaScripts,
              icon: const Icon(Icons.refresh, size: 14),
              label: const Text('Reload'),
            ),
          ],
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (_fridaCategories != null && _fridaCategories!.isNotEmpty)
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 4),
            child: Wrap(
              spacing: 6,
              runSpacing: 6,
              children: [
                FilterChip(
                  label: const Text('All', style: TextStyle(fontSize: 11)),
                  selected: _fridaSelectedCategory == null,
                  onSelected: (_) =>
                      setState(() => _fridaSelectedCategory = null),
                  visualDensity: VisualDensity.compact,
                  materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                ..._fridaCategories!.map((cat) => FilterChip(
                      label: Text(cat, style: const TextStyle(fontSize: 11)),
                      selected: _fridaSelectedCategory == cat,
                      onSelected: (_) => setState(() => _fridaSelectedCategory =
                          _fridaSelectedCategory == cat ? null : cat),
                      visualDensity: VisualDensity.compact,
                      materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                    )),
              ],
            ),
          ),
        const Divider(height: 1),
        Expanded(
          child: Builder(builder: (context) {
            final filtered = _fridaSelectedCategory == null
                ? _fridaScripts!
                : _fridaScripts!
                    .where((s) => s['category'] == _fridaSelectedCategory)
                    .toList();
            return ListView.builder(
              padding: const EdgeInsets.all(8),
              itemCount: filtered.length,
              itemBuilder: (ctx, i) {
                final script = filtered[i];
                final name = script['name']?.toString() ?? 'Script ${i + 1}';
                final desc = script['description']?.toString() ?? '';
                final category = script['category']?.toString() ?? '';
                final id = script['id']?.toString() ?? '';
                final isSelected = _fridaSelectedScript == id;

                return Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Container(
                    decoration: BoxDecoration(
                      color: isSelected
                          ? theme.colorScheme.primary.withValues(alpha: 0.08)
                          : theme.colorScheme.surfaceContainerHighest
                              .withValues(alpha: 0.3),
                      borderRadius: BorderRadius.circular(6),
                      border: isSelected
                          ? Border.all(
                              color: theme.colorScheme.primary
                                  .withValues(alpha: 0.4))
                          : null,
                    ),
                    child: ListTile(
                      dense: true,
                      visualDensity: const VisualDensity(vertical: -2),
                      title: Text(name,
                          style: theme.textTheme.bodySmall
                              ?.copyWith(fontWeight: FontWeight.w600)),
                      subtitle: desc.isNotEmpty
                          ? Text(desc,
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: theme.textTheme.bodySmall
                                  ?.copyWith(fontSize: 11, color: Colors.grey))
                          : null,
                      trailing: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          if (category.isNotEmpty)
                            Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 5, vertical: 1),
                              decoration: BoxDecoration(
                                color: theme.colorScheme.primary
                                    .withValues(alpha: 0.1),
                                borderRadius: BorderRadius.circular(3),
                              ),
                              child: Text(category,
                                  style: const TextStyle(fontSize: 9)),
                            ),
                          const SizedBox(width: 4),
                          IconButton(
                            icon: const Icon(Icons.copy, size: 14),
                            tooltip: 'Copy script',
                            visualDensity: VisualDensity.compact,
                            padding: EdgeInsets.zero,
                            constraints: const BoxConstraints(
                                minWidth: 28, minHeight: 28),
                            onPressed: () async {
                              try {
                                final api = ref.read(apiServiceProvider);
                                final full = await api.getFridaScript(id);
                                final code = full['code']?.toString() ?? '';
                                if (code.isNotEmpty) {
                                  Clipboard.setData(ClipboardData(text: code));
                                  if (context.mounted) {
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      SnackBar(
                                          content: Text('$name copied'),
                                          duration: const Duration(seconds: 1)),
                                    );
                                  }
                                }
                              } catch (e) {
                                if (context.mounted) {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(content: Text('Error: $e')),
                                  );
                                }
                              }
                            },
                          ),
                        ],
                      ),
                      onTap: () => setState(
                          () => _fridaSelectedScript = isSelected ? null : id),
                    ),
                  ),
                );
              },
            );
          }),
        ),
        if (_fridaSelectedScript != null) ...[
          const Divider(height: 1),
          Container(
            padding: const EdgeInsets.all(10),
            color: theme.colorScheme.surfaceContainerHighest
                .withValues(alpha: 0.2),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Icon(Icons.play_arrow,
                        size: 14, color: theme.colorScheme.primary),
                    const SizedBox(width: 4),
                    Text('Run on Device',
                        style: theme.textTheme.labelMedium
                            ?.copyWith(fontWeight: FontWeight.w600)),
                  ],
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _fridaSerialController,
                        decoration: const InputDecoration(
                          labelText: 'Device serial',
                          hintText: 'emulator-5554',
                          isDense: true,
                          contentPadding:
                              EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                          border: OutlineInputBorder(),
                        ),
                        style: const TextStyle(fontSize: 12),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: TextField(
                        controller: _fridaTargetController,
                        decoration: const InputDecoration(
                          labelText: 'Target package',
                          hintText: 'com.example.app',
                          isDense: true,
                          contentPadding:
                              EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                          border: OutlineInputBorder(),
                        ),
                        style: const TextStyle(fontSize: 12),
                      ),
                    ),
                    const SizedBox(width: 8),
                    FilledButton.icon(
                      onPressed: _fridaRunning
                          ? null
                          : () => _runFridaScript(_fridaSelectedScript!),
                      icon: _fridaRunning
                          ? const SizedBox(
                              width: 12,
                              height: 12,
                              child: CircularProgressIndicator(strokeWidth: 2))
                          : const Icon(Icons.play_arrow, size: 14),
                      label: const Text('Run', style: TextStyle(fontSize: 12)),
                      style: FilledButton.styleFrom(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 8),
                        visualDensity: VisualDensity.compact,
                      ),
                    ),
                  ],
                ),
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
                    child: Stack(
                      children: [
                        SingleChildScrollView(
                          padding: const EdgeInsets.all(8),
                          child: SelectableText(
                            _fridaRunOutput!,
                            style: TextStyle(
                              fontSize: 11,
                              fontFamily: 'monospace',
                              color: _fridaRunOutput!.startsWith('Error')
                                  ? theme.colorScheme.error
                                  : null,
                            ),
                          ),
                        ),
                        Positioned(
                          top: 2,
                          right: 2,
                          child: IconButton(
                            icon: const Icon(Icons.copy, size: 12),
                            tooltip: 'Copy output',
                            visualDensity: VisualDensity.compact,
                            padding: EdgeInsets.zero,
                            constraints: const BoxConstraints(
                                minWidth: 24, minHeight: 24),
                            onPressed: () {
                              Clipboard.setData(
                                  ClipboardData(text: _fridaRunOutput!));
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(
                                    content: Text('Output copied'),
                                    duration: Duration(seconds: 1)),
                              );
                            },
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ],
    );
  }

  Future<void> _runFridaScript(String scriptId) async {
    final serial = _fridaSerialController.text.trim();
    final target = _fridaTargetController.text.trim();
    if (serial.isEmpty || target.isEmpty) {
      setState(() => _fridaRunOutput =
          'Error: device serial and target package are required');
      return;
    }
    setState(() {
      _fridaRunning = true;
      _fridaRunOutput = 'Running script...';
      _fridaEvidenceData = null;
      _fridaEvidencePersisted = false;
      _fridaEvidencePersistError = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final apkId = ref.read(apkProvider).selected?.id;
      final res =
          await api.runFridaScript(scriptId, serial, target, apkId: apkId);
      final output = res['output']?.toString() ?? '';
      final error = res['error']?.toString();
      final evidence = _asStringMap(res['evidence']);
      setState(() {
        _fridaRunning = false;
        _fridaEvidenceData = evidence.isEmpty ? null : evidence;
        _fridaEvidencePersisted = res['evidence_persisted'] == true;
        _fridaEvidencePersistError = res['evidence_persist_error']?.toString();
        _fridaRunOutput = error != null
            ? 'Error: $error\n$output'
            : output.isEmpty
                ? '(no output)'
                : output;
      });
    } catch (e) {
      setState(() {
        _fridaRunning = false;
        _fridaEvidenceData = null;
        _fridaEvidencePersisted = false;
        _fridaEvidencePersistError = null;
        _fridaRunOutput = 'Error: $e';
      });
    }
  }

  Future<void> _loadFridaScripts() async {
    setState(() => _fridaLoading = true);
    try {
      final api = ref.read(apiServiceProvider);
      final scripts = await api.listFridaScripts();
      final categories = await api.listFridaCategories();
      setState(() {
        _fridaScripts = scripts;
        _fridaCategories = categories;
        _fridaLoading = false;
      });
    } catch (e) {
      setState(() {
        _fridaLoading = false;
        _fridaScripts = [];
      });
    }
  }

  Widget _buildMitmInstructions(ThemeData theme) {
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
        style: theme.textTheme.bodySmall
            ?.copyWith(fontFamily: 'monospace', height: 1.8),
      ),
    );
  }

  Future<void> _startMitmproxy() async {
    final port = _mitmportController.text.trim();
    if (port.isEmpty) {
      setState(() => _mitmResult = 'Error: port is required');
      return;
    }
    setState(() {
      _mitmRunning = true;
      _mitmResult = 'Starting mitmproxy on port $port...';
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api
          .shellCommand('mitmdump -p $port --set block_global=false &');
      setState(() {
        _mitmResult = 'Proxy running on port $port\n${res['output'] ?? ''}';
      });
    } catch (e) {
      setState(() {
        _mitmResult = 'Error: $e';
        _mitmRunning = false;
      });
    }
  }

  Future<void> _stopMitmproxy() async {
    setState(() {
      _mitmRunning = false;
      _mitmResult = 'Stopping...';
    });
    try {
      final api = ref.read(apiServiceProvider);
      await api.shellCommand('pkill -f mitmdump || true');
      setState(() => _mitmResult = 'Proxy stopped.');
    } catch (e) {
      setState(() => _mitmResult = 'Stop error: $e');
    }
  }

  Widget _renderAnalyzer(
      String type, Map<String, dynamic> data, ThemeData theme) {
    switch (type) {
      case 'manifest':
        return _renderManifest(data, theme);
      case 'certificate':
        return _renderCertificate(data, theme);
      case 'risk':
        return _renderRisk(data, theme);
      case 'attack_surface':
        return _renderAttackSurface(data, theme);
      case 'entry_trace':
        return _renderEntryTrace(data, theme);
      case 'packer':
        return _renderPacker(data, theme);
      case 'code':
        return _renderCode(data, theme);
      case 'sdk':
        return _renderSDK(data, theme);
      case 'strings':
        return _renderStrings(data, theme);
      case 'antidetect':
        return _renderAntiDetect(data, theme);
      case 'triage':
        return _renderTriage(data, theme);
      default:
        return Text('Unknown analyzer: $type',
            style: theme.textTheme.bodySmall);
    }
  }

  Widget _renderTriage(Map<String, dynamic> data, ThemeData theme) {
    final apk = _asStringMap(data['apk']);
    final coverage = _asStringMap(data['coverage']);
    final findings = _asStringMap(data['findings']);
    final nextSteps = _asStringList(data['next_steps']);
    final risk = _asStringMap(findings['risk']);
    final manifest = _asStringMap(findings['manifest']);
    final code = _asStringMap(findings['code']);
    final strings = _asStringMap(findings['strings']);
    final packer = _asStringMap(findings['packer']);
    final antiDetect = _asStringMap(
      findings['antidetect'] ?? findings['anti_detect'],
    );
    final hooks = _asStringMap(findings['generated_hooks']);
    final callGraph = _asStringMap(findings['callgraph']);
    final attackSurface = _asStringMap(findings['attack_surface']);
    final attackSummary = _asStringMap(attackSurface['summary']);
    final entryTrace = _asStringMap(findings['entry_trace']);
    final entryTraceSummary = _asStringMap(entryTrace['summary']);
    final runtimeEvidence = _asStringMap(findings['runtime_evidence']);

    final score =
        (risk['score'] is num) ? (risk['score'] as num).toDouble() : 0.0;
    final riskColor = score >= 60
        ? theme.colorScheme.error
        : score >= 30
            ? Colors.orange
            : Colors.green;
    final packageName =
        (manifest['package'] ?? apk['package_name'] ?? '').toString();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              flex: 2,
              child: _triageCard(
                'Target',
                Icons.android,
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    SelectableText(
                      packageName.isEmpty ? 'Unknown package' : packageName,
                      style: theme.textTheme.titleSmall
                          ?.copyWith(fontFamily: 'monospace'),
                    ),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 6,
                      runSpacing: 4,
                      children: [
                        if ((apk['filename'] ?? '').toString().isNotEmpty)
                          _kvChip('file', apk['filename'].toString(), theme),
                        if ((apk['decompiled_tool'] ?? '')
                            .toString()
                            .isNotEmpty)
                          _kvChip('decompiled',
                              apk['decompiled_tool'].toString(), theme),
                        if ((apk['version_name'] ?? '').toString().isNotEmpty)
                          _kvChip(
                              'version', apk['version_name'].toString(), theme),
                      ],
                    ),
                  ],
                ),
                theme,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _triageCard(
                'Risk Score',
                Icons.speed,
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '${score.toStringAsFixed(0)} / 100',
                      style: theme.textTheme.headlineSmall
                          ?.copyWith(color: riskColor),
                    ),
                    const SizedBox(height: 8),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(4),
                      child: LinearProgressIndicator(
                        value: (score / 100).clamp(0.0, 1.0),
                        color: riskColor,
                        backgroundColor: theme.dividerColor,
                        minHeight: 6,
                      ),
                    ),
                  ],
                ),
                theme,
                accent: riskColor,
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        if (nextSteps.isNotEmpty)
          _triageCard(
            'Agent next steps',
            Icons.route,
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: nextSteps
                  .map(
                    (s) => Padding(
                      padding: const EdgeInsets.only(bottom: 6),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Padding(
                            padding: EdgeInsets.only(top: 2),
                            child: Icon(Icons.arrow_right, size: 16),
                          ),
                          Expanded(
                            child: SelectableText(
                              s,
                              style: theme.textTheme.bodySmall,
                            ),
                          ),
                        ],
                      ),
                    ),
                  )
                  .toList(),
            ),
            theme,
            accent: theme.colorScheme.primary,
          ),
        const SizedBox(height: 12),
        _triageCard(
          'Coverage',
          Icons.checklist,
          Wrap(
            spacing: 6,
            runSpacing: 6,
            children: coverage.entries
                .map((e) => _coverageChip(e.key, e.value.toString(), theme))
                .toList(),
          ),
          theme,
        ),
        const SizedBox(height: 12),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            _triageMetric(
              'Secrets',
              _countLabel(code['secrets_count']),
              Icons.key,
              theme,
              danger: _num(code['secrets_count']) > 0,
            ),
            _triageMetric(
              'Dangerous APIs',
              _countLabel(code['dangerous_api_count']),
              Icons.warning_amber,
              theme,
              danger: _num(code['dangerous_api_count']) > 0,
            ),
            _triageMetric(
              'Crypto',
              _countLabel(strings['crypto_usage_count']),
              Icons.lock,
              theme,
              danger: _num(strings['crypto_usage_count']) > 0,
            ),
            _triageMetric(
              'Attack Surface',
              _countLabel(attackSummary['unprotected']),
              Icons.hub,
              theme,
              danger: _num(attackSummary['unprotected']) > 0,
            ),
            _triageMetric(
              'Entry Trace',
              _countLabel(entryTraceSummary['flows_found']),
              Icons.route,
              theme,
              danger: (entryTraceSummary['risk_level'] ?? '') == 'high',
            ),
            _triageMetric(
              'Hooks',
              _countLabel(hooks['count']),
              Icons.auto_fix_high,
              theme,
            ),
            _triageMetric(
              'Runtime hits',
              _countLabel(runtimeEvidence['entry_trace']),
              Icons.fact_check,
              theme,
              danger: _num(runtimeEvidence['entry_trace']) > 0,
            ),
          ],
        ),
        const SizedBox(height: 12),
        _triageFindingsSection(
            'Manifest signals',
            [
              if (_asStringList(manifest['dangerous_permissions']).isNotEmpty)
                _triageFindingLine(
                  'Dangerous permissions',
                  _asStringList(manifest['dangerous_permissions']).join(', '),
                  theme,
                  danger: true,
                ),
              if (_asMapList(manifest['exported_components']).isNotEmpty)
                _triageFindingLine(
                  'Exported components',
                  '${_asMapList(manifest['exported_components']).length} exposed component(s)',
                  theme,
                  danger: true,
                ),
              if (manifest['debuggable'] == true)
                _triageFindingLine(
                    'Debuggable', 'android:debuggable=true', theme,
                    danger: true),
              if (manifest['allow_backup'] == true)
                _triageFindingLine('Backup', 'android:allowBackup=true', theme,
                    danger: true),
              if (manifest['uses_cleartext_traffic'] == true)
                _triageFindingLine(
                    'Cleartext traffic', 'HTTP cleartext is enabled', theme,
                    danger: true),
            ],
            theme),
        _triageFindingsSection(
          'Risk findings',
          _asMapList(risk['top_findings'])
              .map((r) => _triageFindingLine(
                    (r['title'] ?? r['code'] ?? 'Risk').toString(),
                    (r['description'] ?? '').toString(),
                    theme,
                    tag: (r['level'] ?? '').toString().toUpperCase(),
                    danger: r['level'] == 'high',
                  ))
              .toList(),
          theme,
        ),
        _triageFindingsSection(
            'Protection & packing',
            [
              if (packer['has_packer'] == true)
                _triageFindingLine(
                  'Packer detected',
                  _asMapList(packer['detected'])
                      .map((p) => p['name'].toString())
                      .join(', '),
                  theme,
                  danger: true,
                ),
              if (_asStringMap(antiDetect['summary']).isNotEmpty)
                _triageFindingLine(
                  'Anti-analysis',
                  '${_asStringMap(antiDetect['summary'])['total_findings'] ?? 0} finding(s), level: ${_asStringMap(antiDetect['summary'])['protection_level'] ?? 'unknown'}',
                  theme,
                  danger: (_asStringMap(antiDetect['summary'])['total_findings']
                              as num?)
                          ?.toInt() !=
                      0,
                ),
            ],
            theme),
        if (attackSurface.isNotEmpty)
          _triageFindingsSection(
            'Attack surface',
            [
              _triageFindingLine(
                'Summary',
                'exported=${_num(attackSummary['exported_activities']) + _num(attackSummary['exported_services']) + _num(attackSummary['exported_receivers']) + _num(attackSummary['exported_providers'])}, '
                    'deeplinks=${_num(attackSummary['deep_links'])}, '
                    'unprotected=${_num(attackSummary['unprotected'])}, '
                    'risk=${attackSummary['risk_level'] ?? 'unknown'}',
                theme,
                danger: (attackSummary['risk_level'] ?? '') == 'high',
              ),
              ..._asMapList(attackSurface['entry_points']).take(5).map(
                    (e) => _triageFindingLine(
                      (e['name'] ?? '').toString(),
                      '${e['kind'] ?? ''} / ${e['reason'] ?? ''}',
                      theme,
                      tag: (e['risk'] ?? '').toString().toUpperCase(),
                      danger: e['risk'] == 'high',
                    ),
                  ),
              ..._asMapList(attackSurface['suggested_tests']).take(3).map(
                    (t) => _triageFindingLine(
                      'ADB test',
                      (t['command'] ?? '').toString(),
                      theme,
                      tag: (t['kind'] ?? '').toString(),
                    ),
                  ),
            ],
            theme,
          ),
        if (entryTrace.isNotEmpty)
          _triageFindingsSection(
            'Entry trace',
            [
              _triageFindingLine(
                'Summary',
                'components=${_num(entryTraceSummary['components'])}, '
                    'files=${_num(entryTraceSummary['files_matched'])}, '
                    'handlers=${_num(entryTraceSummary['handlers_found'])}, '
                    'inputs=${_num(entryTraceSummary['input_signals_found'])}, '
                    'sinks=${_num(entryTraceSummary['sink_signals_found'])}, '
                    'flows=${_num(entryTraceSummary['flows_found'])}, '
                    'risk=${entryTraceSummary['risk_level'] ?? 'unknown'}',
                theme,
                danger: (entryTraceSummary['risk_level'] ?? '') == 'high',
              ),
              ..._asMapList(entryTrace['traces']).take(5).map(
                    (t) => _triageFindingLine(
                      (t['component'] ?? '').toString(),
                      '${t['kind'] ?? ''} / flows=${_asMapList(t['flows']).length} / ${t['reason'] ?? ''}',
                      theme,
                      tag: (t['risk'] ?? '').toString().toUpperCase(),
                      danger: t['risk'] == 'high',
                    ),
                  ),
            ],
            theme,
          ),
        if (runtimeEvidence.isNotEmpty)
          _triageFindingsSection(
            'Runtime evidence',
            [
              _triageFindingLine(
                'ENTRY_TRACE hits',
                '${_num(runtimeEvidence['entry_trace'])} hit(s), flows=${_asStringList(runtimeEvidence['flow_ids']).join(', ')}, hook=${runtimeEvidence['hook_id'] ?? ''}',
                theme,
                tag: 'DYNAMIC',
                danger: _num(runtimeEvidence['entry_trace']) > 0,
              ),
              ..._asMapList(runtimeEvidence['events']).take(5).map(
                    (e) => _triageFindingLine(
                      '[${e['kind'] ?? ''}] ${e['operation'] ?? ''}',
                      [
                        if (_asStringList(e['flow_ids']).isNotEmpty)
                          'flows=${_asStringList(e['flow_ids']).join(',')}',
                        (e['value'] ?? '').toString(),
                      ].where((v) => v.isNotEmpty).join('  '),
                      theme,
                      tag: 'HIT',
                      danger: true,
                    ),
                  ),
              ..._asMapList(runtimeEvidence['verified_flows']).take(5).map(
                (f) {
                  final source = _asStringMap(f['source']);
                  final sink = _asStringMap(f['sink']);
                  return _triageFindingLine(
                    'Verified ${f['flow_id'] ?? 'flow'}',
                    '${f['component'] ?? ''}.${f['method'] ?? ''}  ${source['kind'] ?? ''}:${source['line'] ?? ''} → ${sink['kind'] ?? ''}:${sink['line'] ?? ''} ${sink['pattern'] ?? ''}',
                    theme,
                    tag: (f['risk'] ?? 'HIT').toString().toUpperCase(),
                    danger: true,
                  );
                },
              ),
            ],
            theme,
          ),
        _triageFindingsSection(
            'Static code signals',
            [
              ..._asMapList(code['secrets_sample']).take(5).map(
                    (s) => _triageFindingLine(
                      (s['kind'] ?? 'secret').toString(),
                      '${s['file'] ?? ''}:${s['line'] ?? ''} ${s['value'] ?? ''}',
                      theme,
                      danger: true,
                    ),
                  ),
              ..._asMapList(code['dangerous_api_sample']).take(5).map(
                    (s) => _triageFindingLine(
                      (s['pattern'] ?? 'dangerous_api').toString(),
                      '${s['file'] ?? ''}:${s['line'] ?? ''}',
                      theme,
                      danger: true,
                    ),
                  ),
              ..._asMapList(strings['crypto_sample']).take(5).map(
                    (c) => _triageFindingLine(
                      '${c['algorithm'] ?? 'crypto'} / ${c['strength'] ?? ''}',
                      '${c['file'] ?? ''}:${c['line'] ?? ''}',
                      theme,
                      danger: c['strength'] == 'weak',
                    ),
                  ),
            ],
            theme),
        if (callGraph.isNotEmpty)
          _triageFindingsSection(
              'Call graph',
              [
                _triageFindingLine(
                  'Stats',
                  _asStringMap(callGraph['stats'])
                      .entries
                      .map((e) => '${e.key}: ${e.value}')
                      .join(', '),
                  theme,
                ),
              ],
              theme),
        if (hooks.isNotEmpty)
          _triageFindingsSection(
            'Generated Frida hook ideas',
            _asMapList(hooks['sample'])
                .map((h) => _triageFindingLine(
                      (h['name'] ?? h['id'] ?? 'hook').toString(),
                      (h['reason'] ?? h['description'] ?? '').toString(),
                      theme,
                      tag: (h['category'] ?? '').toString(),
                    ))
                .toList(),
            theme,
          ),
        _expandable(
          'Raw triage JSON',
          [
            Row(
              children: [
                TextButton.icon(
                  onPressed: () {
                    final text =
                        const JsonEncoder.withIndent('  ').convert(data);
                    Clipboard.setData(ClipboardData(text: text));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                          content: Text('Triage JSON copied'),
                          duration: Duration(seconds: 1)),
                    );
                  },
                  icon: const Icon(Icons.copy, size: 14),
                  label: const Text('Copy JSON'),
                ),
              ],
            ),
            SelectableText(
              const JsonEncoder.withIndent('  ').convert(data),
              style: theme.textTheme.bodySmall
                  ?.copyWith(fontFamily: 'monospace', fontSize: 11),
            ),
          ],
          theme,
        ),
      ],
    );
  }

  Map<String, dynamic> _asStringMap(dynamic raw) {
    if (raw is Map<String, dynamic>) {
      return raw;
    }
    if (raw is Map) {
      return raw.map((k, v) => MapEntry(k.toString(), v));
    }
    return {};
  }

  List<String> _asStringList(dynamic raw) {
    if (raw is List) {
      return raw.map((e) => e.toString()).toList();
    }
    return const [];
  }

  List<Map<String, dynamic>> _asMapList(dynamic raw) {
    if (raw is! List) {
      return const [];
    }
    return raw
        .whereType<Map>()
        .map((m) => m.map((k, v) => MapEntry(k.toString(), v)))
        .toList();
  }

  int _num(dynamic raw) {
    if (raw is int) {
      return raw;
    }
    if (raw is num) {
      return raw.toInt();
    }
    return int.tryParse(raw?.toString() ?? '') ?? 0;
  }

  String _countLabel(dynamic raw) => _num(raw).toString();

  Widget _triageCard(
    String title,
    IconData icon,
    Widget child,
    ThemeData theme, {
    Color? accent,
  }) {
    final border = accent ?? theme.colorScheme.primary;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color:
            theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.32),
        borderRadius: BorderRadius.circular(10),
        border: Border(left: BorderSide(color: border, width: 3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: border),
              const SizedBox(width: 8),
              Text(title,
                  style: theme.textTheme.titleSmall
                      ?.copyWith(fontWeight: FontWeight.w600)),
            ],
          ),
          const SizedBox(height: 10),
          child,
        ],
      ),
    );
  }

  Widget _coverageChip(String key, String status, ThemeData theme) {
    final low = status.toLowerCase();
    final ok = low == 'ok';
    final skipped = low.startsWith('skipped');
    final color = ok
        ? Colors.green
        : skipped
            ? Colors.orange
            : theme.colorScheme.error;
    return Tooltip(
      message: status,
      child: Chip(
        avatar: Icon(
          ok
              ? Icons.check_circle
              : skipped
                  ? Icons.pause_circle
                  : Icons.error_outline,
          size: 14,
          color: color,
        ),
        label: Text(key, style: const TextStyle(fontSize: 11)),
        backgroundColor: color.withValues(alpha: 0.12),
        visualDensity: VisualDensity.compact,
      ),
    );
  }

  Widget _triageMetric(
    String label,
    String value,
    IconData icon,
    ThemeData theme, {
    bool danger = false,
  }) {
    final color = danger ? theme.colorScheme.error : theme.colorScheme.primary;
    return Container(
      constraints: const BoxConstraints(minWidth: 120),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.24)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 16, color: color),
          const SizedBox(width: 8),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label,
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: Colors.grey.shade700)),
              Text(value,
                  style: theme.textTheme.titleMedium
                      ?.copyWith(fontWeight: FontWeight.w700)),
            ],
          ),
        ],
      ),
    );
  }

  Widget _triageFindingsSection(
    String title,
    List<Widget> children,
    ThemeData theme,
  ) {
    if (children.isEmpty) {
      return const SizedBox.shrink();
    }
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: _triageCard(
        title,
        Icons.find_in_page,
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: children,
        ),
        theme,
      ),
    );
  }

  Widget _triageFindingLine(
    String title,
    String detail,
    ThemeData theme, {
    String? tag,
    bool danger = false,
  }) {
    final color = danger ? theme.colorScheme.error : theme.colorScheme.primary;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 6,
            height: 6,
            margin: const EdgeInsets.only(top: 7),
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        title,
                        style: theme.textTheme.bodyMedium
                            ?.copyWith(fontWeight: FontWeight.w600),
                      ),
                    ),
                    if ((tag ?? '').isNotEmpty)
                      Container(
                        margin: const EdgeInsets.only(left: 8),
                        padding: const EdgeInsets.symmetric(
                            horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: color.withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          tag!,
                          style: TextStyle(
                            fontSize: 10,
                            color: color,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                  ],
                ),
                if (detail.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 2),
                    child: SelectableText(
                      detail,
                      style: theme.textTheme.bodySmall
                          ?.copyWith(color: Colors.grey.shade700),
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _renderEntryTrace(Map<String, dynamic> data, ThemeData theme) {
    final summary = _asStringMap(data['summary']);
    final traces = _asMapList(data['traces']);
    final risk = (summary['risk_level'] ?? 'unknown').toString();
    final riskColor = risk == 'high'
        ? theme.colorScheme.error
        : risk == 'medium'
            ? Colors.orange
            : theme.colorScheme.primary;

    Widget commandBlock(String command) {
      return Container(
        width: double.infinity,
        margin: const EdgeInsets.only(top: 6),
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color:
              theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: SelectableText(
                command,
                style: theme.textTheme.bodySmall
                    ?.copyWith(fontFamily: 'monospace', fontSize: 11),
              ),
            ),
            IconButton(
              tooltip: 'Copy command',
              icon: const Icon(Icons.copy, size: 14),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: command));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                      content: Text('Command copied'),
                      duration: Duration(seconds: 1)),
                );
              },
            ),
          ],
        ),
      );
    }

    Widget signalLine(Map<String, dynamic> signal) {
      final title =
          '${signal['kind'] ?? 'signal'} / ${signal['pattern'] ?? ''}';
      final file = (signal['file'] ?? '').toString();
      final line = (signal['line'] ?? '').toString();
      final evidence = (signal['evidence'] ?? '').toString();
      final where = file.isEmpty ? '' : '$file:$line';
      return _triageFindingLine(
        title,
        [where, evidence].where((v) => v.isNotEmpty).join('  '),
        theme,
        tag: line.isEmpty ? null : 'L$line',
      );
    }

    Widget flowLine(Map<String, dynamic> flow) {
      final source = _asStringMap(flow['source']);
      final sink = _asStringMap(flow['sink']);
      final variables = _asStringList(flow['variables']);
      final sourceLine = (source['line'] ?? '').toString();
      final sinkLine = (sink['line'] ?? '').toString();
      final file = (flow['file'] ?? source['file'] ?? '').toString();
      final risk = (flow['risk'] ?? '').toString();
      final detail = [
        if (file.isNotEmpty) '$file:$sourceLine → $sinkLine',
        if (variables.isNotEmpty) 'via ${variables.join(', ')}',
        (flow['reason'] ?? '').toString(),
      ].where((v) => v.isNotEmpty).join('  ');
      return _triageFindingLine(
        '${source['kind'] ?? 'source'}:${source['pattern'] ?? ''} → ${sink['kind'] ?? 'sink'}:${sink['pattern'] ?? ''}',
        detail,
        theme,
        tag: risk.toUpperCase(),
        danger: risk == 'high',
      );
    }

    List<Widget> signalSection(
      String title,
      List<Map<String, dynamic>> signals, {
      bool danger = false,
    }) {
      if (signals.isEmpty) return const [];
      return [
        const SizedBox(height: 8),
        _expandable(
          '$title (${signals.length})',
          signals.take(20).map(signalLine).toList(),
          theme,
          danger: danger,
        ),
      ];
    }

    Widget traceCard(Map<String, dynamic> trace) {
      final traceRisk = (trace['risk'] ?? 'unknown').toString();
      final traceColor = traceRisk == 'high'
          ? theme.colorScheme.error
          : traceRisk == 'medium'
              ? Colors.orange
              : theme.colorScheme.primary;
      final sourceFiles = _asMapList(trace['source_files']);
      final handlers = _asMapList(trace['handlers']);
      final inputs = _asMapList(trace['inputs']);
      final sinks = _asMapList(trace['sinks']);
      final flows = _asMapList(trace['flows']);
      final commands = _asStringList(trace['commands']);
      final notes = _asStringList(trace['notes']);

      return Container(
        width: double.infinity,
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: traceColor.withValues(alpha: 0.28)),
          color: traceColor.withValues(alpha: 0.06),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.route, size: 16, color: traceColor),
                const SizedBox(width: 8),
                Expanded(
                  child: SelectableText(
                    (trace['component'] ?? '').toString(),
                    style: theme.textTheme.bodyMedium?.copyWith(
                      fontFamily: 'monospace',
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                _kvChip((trace['kind'] ?? '').toString(), traceRisk, theme),
              ],
            ),
            if ((trace['reason'] ?? '').toString().isNotEmpty) ...[
              const SizedBox(height: 6),
              Text((trace['reason'] ?? '').toString(),
                  style: theme.textTheme.bodySmall),
            ],
            const SizedBox(height: 6),
            Wrap(
              spacing: 6,
              runSpacing: 4,
              children: [
                _kvChip('files', sourceFiles.length.toString(), theme),
                _kvChip('handlers', handlers.length.toString(), theme),
                _kvChip('inputs', inputs.length.toString(), theme),
                _kvChip('sinks', sinks.length.toString(), theme),
                _kvChip('flows', flows.length.toString(), theme),
              ],
            ),
            if (sourceFiles.isNotEmpty) ...[
              const SizedBox(height: 8),
              Wrap(
                spacing: 6,
                runSpacing: 4,
                children: sourceFiles
                    .take(6)
                    .map((f) => _kvChip(
                          (f['language'] ?? 'file').toString(),
                          (f['file'] ?? '').toString(),
                          theme,
                        ))
                    .toList(),
              ),
            ],
            if (flows.isNotEmpty) ...[
              const SizedBox(height: 8),
              _expandable(
                'Source → sink flows (${flows.length})',
                flows.take(20).map(flowLine).toList(),
                theme,
                danger: flows.any((f) => f['risk'] == 'high'),
              ),
            ],
            ...signalSection('Handlers', handlers),
            ...signalSection('External inputs', inputs),
            ...signalSection('Sinks', sinks, danger: traceRisk == 'high'),
            if (notes.isNotEmpty) ...[
              const SizedBox(height: 8),
              ...notes.map(
                (n) => Text('• $n', style: theme.textTheme.bodySmall),
              ),
            ],
            ...commands.take(5).map(commandBlock),
          ],
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            _triageMetric('Components', _countLabel(summary['components']),
                Icons.hub, theme),
            _triageMetric('Files', _countLabel(summary['files_matched']),
                Icons.source, theme),
            _triageMetric('Handlers', _countLabel(summary['handlers_found']),
                Icons.account_tree, theme),
            _triageMetric('Inputs', _countLabel(summary['input_signals_found']),
                Icons.input, theme,
                danger: _num(summary['input_signals_found']) > 0),
            _triageMetric('Sinks', _countLabel(summary['sink_signals_found']),
                Icons.outbox, theme,
                danger: _num(summary['sink_signals_found']) > 0),
            _triageMetric('Flows', _countLabel(summary['flows_found']),
                Icons.account_tree, theme,
                danger: _num(summary['flows_found']) > 0),
            _triageMetric('Risk', risk, Icons.speed, theme,
                danger: risk == 'high'),
          ],
        ),
        const SizedBox(height: 12),
        _triageCard(
          'Entry Trace focus',
          Icons.route,
          Text(
            traces.isEmpty
                ? 'No exported entrypoint source files were matched. Decompile with jadx/apktool and rerun Entry Trace.'
                : 'Trace exported component handlers from manifest/attack_surface into source lines, external input reads, source→sink flows, risky sinks, and replay commands.',
            style: theme.textTheme.bodySmall,
          ),
          theme,
          accent: riskColor,
        ),
        const SizedBox(height: 12),
        if (traces.isNotEmpty)
          _triageCard(
            'Traces',
            Icons.route,
            Column(children: traces.map(traceCard).toList()),
            theme,
            accent: riskColor,
          ),
        _expandable(
          'Raw entry_trace JSON',
          [
            Row(
              children: [
                TextButton.icon(
                  onPressed: () {
                    final text =
                        const JsonEncoder.withIndent('  ').convert(data);
                    Clipboard.setData(ClipboardData(text: text));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                          content: Text('Entry Trace JSON copied'),
                          duration: Duration(seconds: 1)),
                    );
                  },
                  icon: const Icon(Icons.copy, size: 14),
                  label: const Text('Copy JSON'),
                ),
              ],
            ),
            SelectableText(
              const JsonEncoder.withIndent('  ').convert(data),
              style: theme.textTheme.bodySmall
                  ?.copyWith(fontFamily: 'monospace', fontSize: 11),
            ),
          ],
          theme,
        ),
      ],
    );
  }

  Widget _renderAttackSurface(Map<String, dynamic> data, ThemeData theme) {
    final summary = _asStringMap(data['summary']);
    final entries = _asMapList(data['entry_points']);
    final deepLinks = _asMapList(data['deep_links']);
    final providers = _asMapList(data['content_uris']);
    final tests = _asMapList(data['suggested_tests']);
    final findings = _asMapList(data['findings']);
    final risk = (summary['risk_level'] ?? 'unknown').toString();
    final riskColor = risk == 'high'
        ? theme.colorScheme.error
        : risk == 'medium'
            ? Colors.orange
            : theme.colorScheme.primary;
    final exportedTotal = _num(summary['exported_activities']) +
        _num(summary['exported_services']) +
        _num(summary['exported_receivers']) +
        _num(summary['exported_providers']);

    Widget commandBlock(String command) {
      return Container(
        width: double.infinity,
        margin: const EdgeInsets.only(top: 6),
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color:
              theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: SelectableText(
                command,
                style: theme.textTheme.bodySmall
                    ?.copyWith(fontFamily: 'monospace', fontSize: 11),
              ),
            ),
            IconButton(
              tooltip: 'Copy command',
              icon: const Icon(Icons.copy, size: 14),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: command));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                      content: Text('Command copied'),
                      duration: Duration(seconds: 1)),
                );
              },
            ),
          ],
        ),
      );
    }

    Widget entryCard(Map<String, dynamic> e) {
      final itemRisk = (e['risk'] ?? '').toString();
      final itemColor = itemRisk == 'high'
          ? theme.colorScheme.error
          : itemRisk == 'medium'
              ? Colors.orange
              : theme.colorScheme.primary;
      final commands = _asStringList(e['commands']);
      final authorities = _asStringList(e['authorities']);
      return Container(
        width: double.infinity,
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: itemColor.withValues(alpha: 0.28)),
          color: itemColor.withValues(alpha: 0.06),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.input, size: 16, color: itemColor),
                const SizedBox(width: 8),
                Expanded(
                  child: SelectableText(
                    (e['name'] ?? '').toString(),
                    style: theme.textTheme.bodyMedium?.copyWith(
                      fontFamily: 'monospace',
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                _kvChip((e['kind'] ?? '').toString(), itemRisk, theme),
              ],
            ),
            const SizedBox(height: 6),
            Text((e['reason'] ?? '').toString(),
                style: theme.textTheme.bodySmall),
            const SizedBox(height: 6),
            Wrap(
              spacing: 6,
              runSpacing: 4,
              children: [
                _kvChip(
                    'exported by', (e['exported_by'] ?? '').toString(), theme),
                if ((e['permission'] ?? '').toString().isNotEmpty)
                  _kvChip('permission', e['permission'].toString(), theme),
                if (authorities.isNotEmpty)
                  _kvChip('authority', authorities.join(', '), theme),
              ],
            ),
            ...commands.take(3).map(commandBlock),
          ],
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            _triageMetric(
                'Exported', exportedTotal.toString(), Icons.hub, theme,
                danger: exportedTotal > 0),
            _triageMetric('Unprotected', _countLabel(summary['unprotected']),
                Icons.lock_open, theme,
                danger: _num(summary['unprotected']) > 0),
            _triageMetric('Deep links', _countLabel(summary['deep_links']),
                Icons.link, theme,
                danger: _num(summary['deep_links']) > 0),
            _triageMetric('Risk', risk, Icons.speed, theme,
                danger: risk == 'high'),
          ],
        ),
        const SizedBox(height: 12),
        _triageCard(
          'Focus',
          Icons.route,
          Wrap(
            spacing: 6,
            runSpacing: 4,
            children: _asStringList(summary['focus']).isEmpty
                ? [
                    Text('No exported attack surface found.',
                        style: theme.textTheme.bodySmall)
                  ]
                : _asStringList(summary['focus'])
                    .map((f) => Chip(
                          label: Text(f, style: const TextStyle(fontSize: 11)),
                          visualDensity: VisualDensity.compact,
                        ))
                    .toList(),
          ),
          theme,
          accent: riskColor,
        ),
        const SizedBox(height: 12),
        if (findings.isNotEmpty)
          _triageFindingsSection(
            'Findings',
            findings
                .map((f) => _triageFindingLine(
                      (f['code'] ?? '').toString(),
                      '${f['component'] ?? ''} — ${f['summary'] ?? ''}',
                      theme,
                      tag: (f['level'] ?? '').toString().toUpperCase(),
                      danger: f['level'] == 'high',
                    ))
                .toList(),
            theme,
          ),
        if (entries.isNotEmpty)
          _triageCard(
            'Exported entry points',
            Icons.input,
            Column(children: entries.map(entryCard).toList()),
            theme,
          ),
        if (deepLinks.isNotEmpty) ...[
          const SizedBox(height: 12),
          _expandable(
            'Deep links / App links (${deepLinks.length})',
            deepLinks
                .map((d) => Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          SelectableText(
                            '${d['scheme'] ?? ''}://${d['host'] ?? ''}${d['path'] ?? ''}',
                            style: theme.textTheme.bodySmall
                                ?.copyWith(fontFamily: 'monospace'),
                          ),
                          if ((d['command'] ?? '').toString().isNotEmpty)
                            commandBlock(d['command'].toString()),
                        ],
                      ),
                    ))
                .toList(),
            theme,
          ),
        ],
        if (providers.isNotEmpty)
          _expandable(
            'Content providers (${providers.length})',
            providers
                .map((p) => Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: SelectableText(
                        '${p['provider'] ?? ''} → ${_asStringList(p['authorities']).join(', ')}',
                        style: theme.textTheme.bodySmall
                            ?.copyWith(fontFamily: 'monospace'),
                      ),
                    ))
                .toList(),
            theme,
            danger: true,
          ),
        if (tests.isNotEmpty)
          _expandable(
            'Suggested adb tests (${tests.length})',
            tests
                .map((t) => Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            '${t['kind'] ?? ''}: ${t['description'] ?? ''}',
                            style: theme.textTheme.bodySmall,
                          ),
                          commandBlock((t['command'] ?? '').toString()),
                        ],
                      ),
                    ))
                .toList(),
            theme,
          ),
      ],
    );
  }

  Widget _renderManifest(Map<String, dynamic> data, ThemeData theme) {
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
            _kvChip('package', data['package'].toString(), theme),
          if (data['version_name'] != null)
            _kvChip('versionName', data['version_name'].toString(), theme),
          if (data['version_code'] != null && data['version_code'] != 0)
            _kvChip('versionCode', data['version_code'].toString(), theme),
          if (data['min_sdk'] != null && data['min_sdk'] != 0)
            _kvChip('minSdk', data['min_sdk'].toString(), theme),
          if (data['target_sdk'] != null && data['target_sdk'] != 0)
            _kvChip('targetSdk', data['target_sdk'].toString(), theme),
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
        _componentList('Activities', activities, theme),
        _componentList('Services', services, theme),
        _componentList('Receivers', receivers, theme),
        _componentList('Providers', providers, theme),
      ],
    );
  }

  Widget _componentList(String title, List items, ThemeData theme) {
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

  Widget _renderCertificate(Map<String, dynamic> data, ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (data['debug'] == true)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: theme.colorScheme.error.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                'Signed with Android debug key',
                style: TextStyle(color: theme.colorScheme.error, fontSize: 12),
              ),
            ),
          ),
        Wrap(spacing: 8, runSpacing: 4, children: [
          if (data['v1_verified'] != null)
            _kvChip('v1', data['v1_verified'].toString(), theme),
          if (data['v2_verified'] != null)
            _kvChip('v2', data['v2_verified'].toString(), theme),
          if (data['v3_verified'] != null)
            _kvChip('v3', data['v3_verified'].toString(), theme),
        ]),
        const SizedBox(height: 8),
        if ((data['subject'] ?? '').toString().isNotEmpty)
          _kv('Subject', data['subject'].toString(), theme),
        if ((data['issuer'] ?? '').toString().isNotEmpty)
          _kv('Issuer', data['issuer'].toString(), theme),
        if ((data['sha1'] ?? '').toString().isNotEmpty)
          _kv('SHA-1', data['sha1'].toString(), theme, mono: true),
        if ((data['sha256'] ?? '').toString().isNotEmpty)
          _kv('SHA-256', data['sha256'].toString(), theme, mono: true),
        if ((data['algorithm'] ?? '').toString().isNotEmpty)
          _kv('Algorithm', data['algorithm'].toString(), theme),
        if ((data['serial_hex'] ?? '').toString().isNotEmpty)
          _kv('Serial', data['serial_hex'].toString(), theme, mono: true),
        if ((data['not_before'] ?? '').toString().isNotEmpty)
          _kv('NotBefore', data['not_before'].toString(), theme),
        if ((data['not_after'] ?? '').toString().isNotEmpty)
          _kv('NotAfter', data['not_after'].toString(), theme),
        if ((data['tool'] ?? '').toString().isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 4),
            child: Text('via ${data['tool']}',
                style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
          ),
      ],
    );
  }

  Widget _renderRisk(Map<String, dynamic> data, ThemeData theme) {
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
                    padding:
                        const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
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

  Widget _renderCode(Map<String, dynamic> data, ThemeData theme) {
    final endpoints = (data['endpoints'] as List?)?.cast<String>() ?? const [];
    final secrets = (data['secrets'] as List?) ?? const [];
    final dangerous = (data['dangerous_apis'] as List?) ?? const [];
    final scanned = data['files_scanned'] ?? 0;
    final truncated = data['truncated'] == true;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(children: [
          _kvChip('files', scanned.toString(), theme),
          if (truncated)
            Padding(
              padding: const EdgeInsets.only(left: 6),
              child: Chip(
                label: const Text('truncated', style: TextStyle(fontSize: 10)),
                backgroundColor: Colors.orange.withValues(alpha: 0.2),
                visualDensity: VisualDensity.compact,
              ),
            ),
        ]),
        const SizedBox(height: 8),
        _expandable(
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
        _expandable(
          'Secrets / Credentials (${secrets.length})',
          secrets.take(50).map((s) => _findingRow(s, theme)).toList(),
          theme,
          danger: secrets.isNotEmpty,
        ),
        _expandable(
          'Dangerous APIs (${dangerous.length})',
          dangerous.take(50).map((s) => _findingRow(s, theme)).toList(),
          theme,
          danger: dangerous.isNotEmpty,
        ),
      ],
    );
  }

  Widget _renderPacker(Map<String, dynamic> data, ThemeData theme) {
    final hasPacker = data['has_packer'] == true;
    final detected = _asMapList(data['detected']);
    final nativeLibs = _asStringList(data['native_libs']);
    final suggestions = _asStringList(data['suggestions']);
    final dexCount = _num(data['dex_count']);
    final multiDex = data['multi_dex'] == true;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: (hasPacker ? theme.colorScheme.error : Colors.green)
                    .withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                hasPacker ? 'PACKER DETECTED' : 'NO KNOWN PACKER',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: hasPacker ? theme.colorScheme.error : Colors.green,
                ),
              ),
            ),
            const SizedBox(width: 8),
            _kvChip('dex', dexCount.toString(), theme),
            if (multiDex) ...[
              const SizedBox(width: 6),
              _kvChip('multiDex', 'true', theme),
            ],
          ],
        ),
        const SizedBox(height: 12),
        if (detected.isNotEmpty)
          _expandable(
            'Detected packers (${detected.length})',
            detected
                .map(
                  (p) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Text(
                              (p['name'] ?? 'unknown').toString(),
                              style: theme.textTheme.bodyMedium
                                  ?.copyWith(fontWeight: FontWeight.w600),
                            ),
                            const SizedBox(width: 8),
                            if ((p['vendor'] ?? '').toString().isNotEmpty)
                              Text(
                                p['vendor'].toString(),
                                style: theme.textTheme.bodySmall
                                    ?.copyWith(color: Colors.grey.shade700),
                              ),
                            const SizedBox(width: 8),
                            if ((p['confidence'] ?? '').toString().isNotEmpty)
                              Container(
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 5, vertical: 1),
                                decoration: BoxDecoration(
                                  color: Colors.orange.withValues(alpha: 0.12),
                                  borderRadius: BorderRadius.circular(3),
                                ),
                                child: Text(
                                  p['confidence'].toString(),
                                  style: const TextStyle(fontSize: 10),
                                ),
                              ),
                          ],
                        ),
                        if (p['evidence'] is List)
                          Padding(
                            padding: const EdgeInsets.only(top: 4),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: (p['evidence'] as List)
                                  .take(10)
                                  .map(
                                    (e) => SelectableText(
                                      e.toString(),
                                      style: theme.textTheme.bodySmall
                                          ?.copyWith(
                                              fontFamily: 'monospace',
                                              fontSize: 11),
                                    ),
                                  )
                                  .toList(),
                            ),
                          ),
                      ],
                    ),
                  ),
                )
                .toList(),
            theme,
            danger: hasPacker,
          ),
        if (suggestions.isNotEmpty)
          _expandable(
            'Suggestions (${suggestions.length})',
            suggestions
                .map(
                  (s) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Padding(
                          padding: EdgeInsets.only(top: 2),
                          child: Icon(Icons.arrow_right, size: 14),
                        ),
                        const SizedBox(width: 6),
                        Expanded(
                          child: SelectableText(
                            s,
                            style: theme.textTheme.bodySmall,
                          ),
                        ),
                      ],
                    ),
                  ),
                )
                .toList(),
            theme,
          ),
        if (nativeLibs.isNotEmpty)
          _expandable(
            'Native libs (${nativeLibs.length})',
            nativeLibs
                .take(40)
                .map(
                  (lib) => SelectableText(
                    lib,
                    style: theme.textTheme.bodySmall
                        ?.copyWith(fontFamily: 'monospace'),
                  ),
                )
                .toList(),
            theme,
          ),
      ],
    );
  }

  Widget _findingRow(dynamic raw, ThemeData theme) {
    final m = raw as Map<String, dynamic>;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
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

  Widget _renderSDK(Map<String, dynamic> data, ThemeData theme) {
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

  Widget _renderStrings(Map<String, dynamic> data, ThemeData theme) {
    final firebase = data['firebase'] as Map<String, dynamic>?;
    final domains =
        (data['domains'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final ips = (data['ips'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final crypto =
        (data['crypto_usage'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final configs =
        (data['configs'] as List?)?.cast<Map<String, dynamic>>() ?? [];
    final filesScanned = data['files_scanned'] ?? 0;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _kvChip('files scanned', filesScanned.toString(), theme),
        const SizedBox(height: 12),
        if (firebase != null) ...[
          Text('Firebase Config', style: theme.textTheme.labelLarge),
          const SizedBox(height: 6),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: theme.colorScheme.surfaceContainerHighest
                  .withValues(alpha: 0.4),
              borderRadius: BorderRadius.circular(6),
              border: const Border(
                  left: BorderSide(color: Colors.orange, width: 3)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if ((firebase['project_id'] ?? '').toString().isNotEmpty)
                  _kv('Project', firebase['project_id'].toString(), theme,
                      mono: true),
                if ((firebase['app_id'] ?? '').toString().isNotEmpty)
                  _kv('App ID', firebase['app_id'].toString(), theme,
                      mono: true),
                if ((firebase['api_key'] ?? '').toString().isNotEmpty)
                  _kv('API Key', firebase['api_key'].toString(), theme,
                      mono: true),
                if ((firebase['storage_bucket'] ?? '').toString().isNotEmpty)
                  _kv('Bucket', firebase['storage_bucket'].toString(), theme,
                      mono: true),
                if ((firebase['database_url'] ?? '').toString().isNotEmpty)
                  _kv('DB URL', firebase['database_url'].toString(), theme,
                      mono: true),
              ],
            ),
          ),
          const SizedBox(height: 12),
        ],
        if (crypto.isNotEmpty) ...[
          _expandable(
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
                      padding: const EdgeInsets.symmetric(
                          horizontal: 5, vertical: 1),
                      decoration: BoxDecoration(
                        color: color.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(3),
                      ),
                      child: Text(strength.toUpperCase(),
                          style: TextStyle(
                              fontSize: 9,
                              color: color,
                              fontWeight: FontWeight.bold)),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(c['algorithm']?.toString() ?? '',
                              style: theme.textTheme.bodySmall
                                  ?.copyWith(fontWeight: FontWeight.w600)),
                          if ((c['file'] ?? '').toString().isNotEmpty)
                            Text('${c['file']}:${c['line'] ?? ''}',
                                style: theme.textTheme.bodySmall?.copyWith(
                                    fontFamily: 'monospace',
                                    fontSize: 10,
                                    color: Colors.grey)),
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
          _expandable(
            'Domains (${domains.length})',
            _groupByCategory(domains, 'host', theme),
            theme,
          ),
        if (ips.isNotEmpty)
          _expandable(
            'IPs (${ips.length})',
            ips
                .map((ip) => Padding(
                      padding: const EdgeInsets.symmetric(vertical: 1),
                      child: Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 5, vertical: 1),
                            decoration: BoxDecoration(
                              color: theme.colorScheme.primary
                                  .withValues(alpha: 0.1),
                              borderRadius: BorderRadius.circular(3),
                            ),
                            child: Text(ip['category']?.toString() ?? '',
                                style: const TextStyle(fontSize: 9)),
                          ),
                          const SizedBox(width: 8),
                          SelectableText(ip['ip']?.toString() ?? '',
                              style: theme.textTheme.bodySmall
                                  ?.copyWith(fontFamily: 'monospace')),
                        ],
                      ),
                    ))
                .toList(),
            theme,
          ),
        if (configs.isNotEmpty)
          _expandable(
            'Config Findings (${configs.length})',
            configs
                .map((c) => Padding(
                      padding: const EdgeInsets.symmetric(vertical: 2),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Container(
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 5, vertical: 1),
                                decoration: BoxDecoration(
                                  color: Colors.orange.withValues(alpha: 0.15),
                                  borderRadius: BorderRadius.circular(3),
                                ),
                                child: Text(c['type']?.toString() ?? '',
                                    style: const TextStyle(fontSize: 9)),
                              ),
                              const SizedBox(width: 6),
                              Expanded(
                                child: SelectableText(
                                    '${c['key']}: ${c['value']}',
                                    style: theme.textTheme.bodySmall
                                        ?.copyWith(fontFamily: 'monospace')),
                              ),
                            ],
                          ),
                          if ((c['file'] ?? '').toString().isNotEmpty)
                            Text(c['file'].toString(),
                                style: theme.textTheme.bodySmall?.copyWith(
                                    fontSize: 10, color: Colors.grey)),
                        ],
                      ),
                    ))
                .toList(),
            theme,
            danger: true,
          ),
      ],
    );
  }

  List<Widget> _groupByCategory(
      List<Map<String, dynamic>> items, String valueKey, ThemeData theme) {
    final grouped = <String, List<String>>{};
    for (final item in items) {
      final cat = (item['category'] ?? 'unknown').toString();
      grouped.putIfAbsent(cat, () => []).add(item[valueKey]?.toString() ?? '');
    }
    return grouped.entries
        .map((e) => Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(e.key,
                      style: theme.textTheme.labelSmall
                          ?.copyWith(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 2),
                  Wrap(
                    spacing: 6,
                    runSpacing: 4,
                    children: e.value
                        .map((v) => Chip(
                              label:
                                  Text(v, style: const TextStyle(fontSize: 10)),
                              visualDensity: VisualDensity.compact,
                              materialTapTargetSize:
                                  MaterialTapTargetSize.shrinkWrap,
                            ))
                        .toList(),
                  ),
                ],
              ),
            ))
        .toList();
  }

  Widget _renderAntiDetect(Map<String, dynamic> data, ThemeData theme) {
    final summary = data['summary'] as Map<String, dynamic>? ?? {};
    final protectionLevel = (summary['protection_level'] ?? 'none').toString();
    final totalFindings = (summary['total_findings'] as num?)?.toInt() ?? 0;

    Color levelColor() {
      switch (protectionLevel) {
        case 'strong':
          return Colors.green.shade700;
        case 'moderate':
          return Colors.orange;
        case 'basic':
          return Colors.amber.shade700;
        default:
          return Colors.red;
      }
    }

    Widget detectionSection(
        String title, IconData icon, List? findings, bool? detected) {
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
                  size: 14,
                  color: detected == true ? Colors.green : Colors.red.shade300),
              const SizedBox(width: 4),
              Text(detected == true ? 'Detected' : 'Not found',
                  style: TextStyle(
                      fontSize: 11,
                      color: detected == true
                          ? Colors.green
                          : Colors.red.shade300)),
            ],
          ),
        );
      }
      return _expandable(
        '$title (${items.length})',
        items
            .map((f) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 3),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 5, vertical: 1),
                            decoration: BoxDecoration(
                              color: Colors.green.withValues(alpha: 0.12),
                              borderRadius: BorderRadius.circular(3),
                            ),
                            child: Text(f['pattern']?.toString() ?? '',
                                style: const TextStyle(
                                    fontSize: 9, fontWeight: FontWeight.w600)),
                          ),
                          const SizedBox(width: 6),
                          if ((f['confidence'] ?? '').toString().isNotEmpty)
                            Text(f['confidence'].toString(),
                                style: TextStyle(
                                    fontSize: 10, color: Colors.grey.shade600)),
                        ],
                      ),
                      if ((f['evidence'] ?? '').toString().isNotEmpty)
                        Padding(
                          padding: const EdgeInsets.only(top: 2),
                          child: SelectableText(f['evidence'].toString(),
                              style: theme.textTheme.bodySmall?.copyWith(
                                  fontFamily: 'monospace', fontSize: 10)),
                        ),
                      if ((f['file'] ?? '').toString().isNotEmpty)
                        Text('${f['file']}:${f['line'] ?? ''}',
                            style: theme.textTheme.bodySmall
                                ?.copyWith(fontSize: 10, color: Colors.grey)),
                    ],
                  ),
                ))
            .toList(),
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
                style: TextStyle(
                    fontSize: 11,
                    color: levelColor(),
                    fontWeight: FontWeight.w600)),
          ),
          const SizedBox(width: 12),
          Text('$totalFindings findings',
              style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
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

  Widget _kvChip(String k, String v, ThemeData theme) {
    return Chip(
      label: Text('$k: $v', style: const TextStyle(fontSize: 11)),
      visualDensity: VisualDensity.compact,
    );
  }

  Widget _kv(String k, String v, ThemeData theme, {bool mono = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 80,
            child: Text(k,
                style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
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

  Widget _expandable(String title, List<Widget> children, ThemeData theme,
      {bool danger = false}) {
    return Theme(
      data: theme.copyWith(dividerColor: Colors.transparent),
      child: ExpansionTile(
        tilePadding: EdgeInsets.zero,
        childrenPadding: const EdgeInsets.only(left: 8, bottom: 8),
        title: Text(title,
            style: theme.textTheme.labelLarge
                ?.copyWith(color: danger ? theme.colorScheme.error : null)),
        children: children.isEmpty
            ? [Text('—', style: theme.textTheme.bodySmall)]
            : children,
      ),
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

class _ResultPanel extends StatelessWidget {
  final String? content;
  final bool isRunning;
  final bool isError;
  final String emptyHint;

  const _ResultPanel({
    required this.content,
    this.isRunning = false,
    this.isError = false,
    this.emptyHint = 'Output will appear here',
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    if (isRunning) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color:
              theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
          borderRadius: BorderRadius.circular(8),
          border: Border(
              left: BorderSide(color: theme.colorScheme.primary, width: 3)),
        ),
        child: const Row(
          children: [
            SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2)),
            SizedBox(width: 12),
            Text('Running...'),
          ],
        ),
      );
    }

    if (content == null || content!.isEmpty) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.all(24),
        alignment: Alignment.center,
        child: Text(emptyHint,
            style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
      );
    }

    final borderColor = isError ? theme.colorScheme.error : Colors.green;
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
        borderRadius: BorderRadius.circular(8),
        border: Border(left: BorderSide(color: borderColor, width: 3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.only(left: 12, right: 4, top: 4),
            child: Row(
              children: [
                Icon(isError ? Icons.error_outline : Icons.check_circle_outline,
                    size: 14, color: borderColor),
                const SizedBox(width: 6),
                Text(isError ? 'Error' : 'Done',
                    style: TextStyle(
                        fontSize: 11,
                        color: borderColor,
                        fontWeight: FontWeight.w600)),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.copy, size: 14),
                  tooltip: 'Copy to clipboard',
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: content!));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                          content: Text('Copied'),
                          duration: Duration(seconds: 1)),
                    );
                  },
                  visualDensity: VisualDensity.compact,
                  padding: EdgeInsets.zero,
                  constraints:
                      const BoxConstraints(minWidth: 28, minHeight: 28),
                ),
              ],
            ),
          ),
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
              child: SelectableText(
                content!,
                style: theme.textTheme.bodySmall
                    ?.copyWith(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _CaptureChip extends StatelessWidget {
  final String label;
  final IconData icon;
  final Color? color;

  const _CaptureChip({required this.label, required this.icon, this.color});

  @override
  Widget build(BuildContext context) {
    final c = color ?? Theme.of(context).colorScheme.onSurface;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: c.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: c),
          const SizedBox(width: 4),
          Text(label,
              style: TextStyle(
                  fontSize: 10, color: c, fontWeight: FontWeight.w500)),
        ],
      ),
    );
  }
}

class _MenuButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool selected;
  final bool running;
  final bool hasResult;
  final bool primary;
  final VoidCallback? onPressed;

  const _MenuButton({
    required this.icon,
    required this.label,
    required this.selected,
    required this.onPressed,
    this.running = false,
    this.hasResult = false,
    this.primary = false,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final disabled = onPressed == null;
    final accent = theme.colorScheme.primary;
    final textColor = disabled
        ? theme.disabledColor
        : (selected || primary ? accent : theme.colorScheme.onSurface);
    final bg = selected
        ? accent.withValues(alpha: 0.14)
        : (primary ? accent.withValues(alpha: 0.06) : null);
    final borderColor = selected
        ? accent.withValues(alpha: 0.6)
        : (primary ? accent.withValues(alpha: 0.4) : theme.dividerColor);

    return InkWell(
      onTap: onPressed,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: borderColor),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (running)
              const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            else
              Icon(icon, size: 16, color: textColor),
            const SizedBox(width: 6),
            Text(
              label,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: textColor,
                fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
              ),
            ),
            if (hasResult && !running) ...[
              const SizedBox(width: 6),
              const Icon(Icons.check_circle, size: 12, color: Colors.green),
            ],
          ],
        ),
      ),
    );
  }
}

class _DecompiledTree extends ConsumerStatefulWidget {
  final String rootDir;
  const _DecompiledTree({required this.rootDir});

  @override
  ConsumerState<_DecompiledTree> createState() => _DecompiledTreeState();
}

class _DecompiledTreeState extends ConsumerState<_DecompiledTree> {
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
            padding: EdgeInsets.only(left: indent, top: 4, bottom: 4, right: 8),
            child: Row(
              children: [
                Icon(
                  _expanded ? Icons.expand_more : Icons.chevron_right,
                  size: 16,
                ),
                Icon(Icons.folder, size: 14, color: theme.colorScheme.primary),
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

  // ===== Reverse Plan =====

  Future<void> _runObjectiveRecommendedTool(ApkInfo apk, Map<String, dynamic> obj) async {
    final tool = (obj['recommended_tool'] ?? '').toString();
    final api = ref.read(apiServiceProvider);
    final notifier = ref.read(apkProvider.notifier);
    try {
      switch (tool) {
        case 'apk_triage':
          setState(() => _analysisAction = 'triage');
          await notifier.runTriage(includeCallgraph: (apk.decompiledPath ?? '').isNotEmpty);
          break;
        case 'apk_attack_surface':
          setState(() => _analysisAction = 'attack_surface');
          await notifier.runAnalyzer('attack_surface');
          break;
        case 'apk_entry_trace':
          setState(() => _analysisAction = 'entry_trace');
          await notifier.runAnalyzer('entry_trace');
          break;
        case 'apk_runtime_plan':
          setState(() => _analysisAction = 'runtime_plan');
          if (_runtimePlanData == null) await _generateRuntimePlan(apk);
          break;
        case 'apk_reverse_validate':
          await _runReverseValidate(apk);
          break;
        default:
          await notifier.runAnalyzer('triage');
      }
      await _loadReversePlan(apk);
    } catch (_) {}
  }

  Future<void> _loadReversePlan(ApkInfo apk) async {
    if (apk.id == null) {
      setState(() => _reversePlanData = {'error': 'APK has no ID'});
      return;
    }
    setState(() {
      _reversePlanRunning = true;
      _reversePlanData = null;
      _reverseValidateData = null;
    });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.reversePlan(apk.id!);
      setState(() {
        _reversePlanData = res;
        _reversePlanRunning = false;
      });
    } catch (e) {
      setState(() {
        _reversePlanData = {'error': e.toString()};
        _reversePlanRunning = false;
      });
    }
  }

  Future<void> _runReverseValidate(ApkInfo apk) async {
    if (apk.id == null) return;
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.reverseValidate(apk.id!);
      setState(() {
        _reverseValidateData = res;
      });
    } catch (e) {
      setState(() {
        _reverseValidateData = {'error': e.toString()};
      });
    }
  }

  Widget _buildReversePlanView(ThemeData theme) {
    if (_reversePlanRunning) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 12),
            Text('Building reverse plan...'),
          ],
        ),
      );
    }

    if (_reversePlanData == null) {
      return Center(
        child: Text(
          'Click Reverse Plan to prioritize objectives, steps, and runtime validation targets before broad exploration.',
          style: theme.textTheme.bodyMedium?.copyWith(color: Colors.grey),
          textAlign: TextAlign.center,
        ),
      );
    }

    if (_reversePlanData!.containsKey('error')) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline, size: 36, color: theme.colorScheme.error),
              const SizedBox(height: 8),
              SelectableText(_reversePlanData!['error'].toString(), style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
            ],
          ),
        ),
      );
    }

    final plan = _reversePlanData!;
    final objectives = _asMapList(plan['objectives']);
    final steps = _asMapList(plan['steps']);
    final missing = _asStringList(plan['missing_analyses']);
    final validate = _asStringMap(_reverseValidateData);
    final unresolved = _asList(validate['unresolved']).map((e) => e.toString()).toList();
    final ready = plan['ready_for_validation'] == true;
    final selected = ref.read(apkProvider).selected;

    Widget objectiveLine(Map<String, dynamic> obj) {
      final objective = (obj['objective'] ?? '').toString();
      final category = (obj['category'] ?? '').toString();
      final status = (obj['status'] ?? '').toString();
      final recommended = (obj['recommended_tool'] ?? '').toString();
      return Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: _triageFindingLine(
              objective,
              [category, recommended].where((v) => v.trim().isNotEmpty).join(' '),
              theme,
              tag: status.toUpperCase(),
              danger: status == 'needs_review' || status == 'pending',
            ),
          ),
          IconButton(
            icon: const Icon(Icons.play_circle, size: 18),
            tooltip: 'Run recommended step',
            visualDensity: VisualDensity.compact,
            onPressed: selected == null ? null : () => _runObjectiveRecommendedTool(selected, obj),
          ),
        ],
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(
            children: [
              Text('Reverse Plan', style: theme.textTheme.titleMedium),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.copy_all, size: 16),
                tooltip: 'Copy plan JSON',
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: const JsonEncoder.withIndent('  ').convert(plan)));
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Reverse plan copied'), duration: Duration(seconds: 1)));
                },
              ),
              IconButton(
                icon: const Icon(Icons.refresh, size: 16),
                tooltip: 'Regenerate',
                onPressed: () {
                  final apk = ref.read(apkProvider).selected;
                  if (apk != null) _loadReversePlan(apk);
                },
              ),
              IconButton(
                icon: const Icon(Icons.verified, size: 16),
                tooltip: 'Validate now',
                onPressed: selected == null ? null : () => _runReverseValidate(selected),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Padding(
          padding: const EdgeInsets.all(12),
          child: Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              _triageMetric('Ready', ready ? 'yes' : 'no', ready ? Icons.check_circle : Icons.info_outline, theme, danger: !ready),
              _triageMetric('Objectives', objectives.length.toString(), Icons.flag, theme),
              _triageMetric('Steps', steps.length.toString(), Icons.checklist, theme),
              _triageMetric('Unresolved', unresolved.length.toString(), Icons.rule, theme, danger: unresolved.isNotEmpty),
            ],
          ),
        ),
        if (missing.isNotEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: missing.map((m) => Chip(label: Text(m))).toList(),
            ),
          ),
        const Divider(height: 1),
        Expanded(
          child: ListView(
            padding: const EdgeInsets.all(12),
            children: [
              Text('Objectives', style: theme.textTheme.titleSmall),
              const SizedBox(height: 8),
              ...objectives.map(objectiveLine),
              const SizedBox(height: 16),
              Text('Steps', style: theme.textTheme.titleSmall),
              const SizedBox(height: 8),
              ...steps.map((step) {
                final order = (step['order'] ?? '').toString();
                final tool = (step['tool'] ?? '').toString();
                final why = (step['why'] ?? '').toString();
                return Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: _triageFindingLine('$order. $tool', why, theme),
                );
              }),
              if (unresolved.isNotEmpty) ...[
                const SizedBox(height: 16),
                Text('Validation gaps', style: theme.textTheme.titleSmall),
                const SizedBox(height: 8),
                ...unresolved.map((u) => _triageFindingLine(u, '', theme, danger: true)),
              ],
            ],
          ),
        ),
      ],
    );
  }

}
