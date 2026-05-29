import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/apk_model.dart';
import '../services/api_service.dart';

const analysisTypes = ['manifest', 'certificate', 'risk', 'code', 'sdk', 'strings', 'antidetect'];

class ApkState {
  final List<ApkInfo> apks;
  final ApkInfo? selected;
  final ApkAnalysis? analysis;
  final bool loading;
  final String? error;
  final String decompileStatus;
  final String? decompileOutputDir;
  final String? decompileTool;
  final Map<String, dynamic> analyses;
  final Set<String> runningAnalyzers;
  final Map<String, String> analyzerErrors;

  const ApkState({
    this.apks = const [],
    this.selected,
    this.analysis,
    this.loading = false,
    this.error,
    this.decompileStatus = '',
    this.decompileOutputDir,
    this.decompileTool,
    this.analyses = const {},
    this.runningAnalyzers = const {},
    this.analyzerErrors = const {},
  });

  ApkState copyWith({
    List<ApkInfo>? apks,
    ApkInfo? selected,
    bool clearSelected = false,
    ApkAnalysis? analysis,
    bool clearAnalysis = false,
    bool? loading,
    String? error,
    String? decompileStatus,
    String? decompileOutputDir,
    String? decompileTool,
    bool clearDecompile = false,
    Map<String, dynamic>? analyses,
    Set<String>? runningAnalyzers,
    Map<String, String>? analyzerErrors,
  }) =>
      ApkState(
        apks: apks ?? this.apks,
        selected: clearSelected ? null : (selected ?? this.selected),
        analysis: clearAnalysis ? null : (analysis ?? this.analysis),
        loading: loading ?? this.loading,
        error: error,
        decompileStatus: clearDecompile ? '' : (decompileStatus ?? this.decompileStatus),
        decompileOutputDir: clearDecompile ? null : (decompileOutputDir ?? this.decompileOutputDir),
        decompileTool: clearDecompile ? null : (decompileTool ?? this.decompileTool),
        analyses: analyses ?? this.analyses,
        runningAnalyzers: runningAnalyzers ?? this.runningAnalyzers,
        analyzerErrors: analyzerErrors ?? this.analyzerErrors,
      );
}

class ApkNotifier extends StateNotifier<ApkState> {
  final ApiService _api;
  final Map<String, ApkAnalysis> _analysisCache = {};
  final Map<String, Map<String, dynamic>> _analysesByApkId = {};

  ApkNotifier(this._api) : super(const ApkState()) {
    refreshApks();
  }

  void clearError() {
    state = state.copyWith(error: null);
  }

  Future<void> refreshApks() async {
    state = state.copyWith(loading: true, error: null);
    try {
      final list = await _api.listApks();
      final apks = list.map(ApkInfo.fromJson).toList();
      ApkInfo? selected = state.selected;
      if (selected != null) {
        selected = apks.firstWhere(
          (a) => a.path == selected!.path,
          orElse: () => apks.isNotEmpty ? apks.first : selected!,
        );
      } else if (apks.isNotEmpty) {
        selected = apks.first;
      }
      state = state.copyWith(
        apks: apks,
        selected: selected,
        analysis: selected != null ? _analysisCache[selected.path] ?? _buildAnalysisFromApk(selected) : null,
        decompileStatus: selected?.decompileTool != null ? 'Done' : '',
        decompileOutputDir: selected?.decompiledPath,
        decompileTool: selected?.decompileTool,
        loading: false,
        analyses: const {},
        runningAnalyzers: const {},
        analyzerErrors: const {},
      );
      if (selected != null && (selected.id ?? '').isNotEmpty) {
        await _loadSavedAnalyses(selected.id!);
      }
    } catch (e) {
      state = state.copyWith(loading: false, error: e.toString());
    }
  }

  Future<void> uploadAndAnalyze(
    String filename, {
    String? filePath,
    List<int>? bytes,
  }) async {
    state = state.copyWith(loading: true, error: null);
    try {
      final result = await _api.uploadAndAnalyze(
        filename,
        filePath: filePath,
        bytes: bytes,
      );
      final apk = ApkInfo.fromJson(result['apk'] ?? result);
      final analysis = ApkAnalysis.fromJson(result['analysis'] ?? result);
      _analysisCache[apk.path] = analysis;

      final existing = state.apks.where((a) => a.path != apk.path).toList()
        ..add(apk);
      state = state.copyWith(
        apks: existing,
        selected: apk,
        analysis: analysis,
        loading: false,
        clearDecompile: true,
        analyses: const {},
        runningAnalyzers: const {},
        analyzerErrors: const {},
      );
      if ((apk.id ?? '').isNotEmpty) {
        await _loadSavedAnalyses(apk.id!);
      }
    } catch (e) {
      state = state.copyWith(loading: false, error: e.toString());
    }
  }

  void selectApk(ApkInfo apk) {
    state = state.copyWith(
      selected: apk,
      analysis: _analysisCache[apk.path] ?? _buildAnalysisFromApk(apk),
      decompileStatus: apk.decompileTool != null ? 'Done' : '',
      decompileOutputDir: apk.decompiledPath,
      decompileTool: apk.decompileTool,
      error: null,
      analyses: _analysesByApkId[apk.id ?? ''] ?? const {},
      runningAnalyzers: const {},
      analyzerErrors: const {},
    );
    if ((apk.id ?? '').isNotEmpty && _analysesByApkId[apk.id!] == null) {
      _loadSavedAnalyses(apk.id!);
    }
  }

  Future<void> removeApk(ApkInfo apk) async {
    _analysisCache.remove(apk.path);
    _analysesByApkId.remove(apk.id ?? '');
    if ((apk.id ?? '').isNotEmpty) {
      try {
        await _api.deleteApk(apk.id!);
      } catch (e) {
        state = state.copyWith(error: 'Delete failed: $e');
        return;
      }
    }
    final remaining = state.apks.where((a) => a.path != apk.path).toList();
    final isSelected = state.selected?.path == apk.path;
    state = state.copyWith(
      apks: remaining,
      clearSelected: isSelected,
      clearAnalysis: isSelected,
      clearDecompile: isSelected,
      analyses: isSelected ? const {} : state.analyses,
      runningAnalyzers: isSelected ? const {} : state.runningAnalyzers,
      analyzerErrors: isSelected ? const {} : state.analyzerErrors,
    );
  }

  Future<void> decompile(String apkPath, {String tool = 'apktool'}) async {
    final selected = state.selected;
    state = state.copyWith(decompileStatus: 'Decompiling...', error: null);
    try {
      final result = await _api.decompileApk(
        apkPath,
        tool: tool,
        id: selected?.id,
      );
      final outDir = (result['output_dir'] ?? result['path'] ?? '').toString();
      ApkInfo? updatedSelected = selected;
      List<ApkInfo> updatedList = state.apks;
      if (selected != null) {
        updatedSelected = selected.copyWith(
          decompiledPath: outDir,
          decompileTool: tool,
        );
        updatedList = state.apks
            .map((a) => a.path == selected.path ? updatedSelected! : a)
            .toList();
      }
      state = state.copyWith(
        apks: updatedList,
        selected: updatedSelected,
        decompileStatus: 'Done',
        decompileOutputDir: outDir,
        decompileTool: tool,
      );
    } catch (e) {
      state = state.copyWith(decompileStatus: 'Failed', error: e.toString());
    }
  }

  Future<void> runAnalyzer(String type) async {
    final apk = state.selected;
    if (apk == null || (apk.id ?? '').isEmpty) return;
    final running = Set<String>.from(state.runningAnalyzers)..add(type);
    final errors = Map<String, String>.from(state.analyzerErrors)..remove(type);
    state = state.copyWith(runningAnalyzers: running, analyzerErrors: errors);
    try {
      final result = await _api.runApkAnalyzer(apk.id!, type);
      final next = Map<String, dynamic>.from(state.analyses);
      next[type] = result;
      _analysesByApkId[apk.id!] = next;
      final r = Set<String>.from(state.runningAnalyzers)..remove(type);
      state = state.copyWith(analyses: next, runningAnalyzers: r);
    } catch (e) {
      final r = Set<String>.from(state.runningAnalyzers)..remove(type);
      final err = Map<String, String>.from(state.analyzerErrors);
      err[type] = e.toString();
      state = state.copyWith(runningAnalyzers: r, analyzerErrors: err);
    }
  }

  Future<void> runAllAnalyzers() async {
    final apk = state.selected;
    if (apk == null || (apk.id ?? '').isEmpty) return;
    final running = Set<String>.from(state.runningAnalyzers)..addAll(analysisTypes);
    state = state.copyWith(runningAnalyzers: running, analyzerErrors: const {});
    try {
      final result = await _api.runApkAnalyzer(apk.id!, 'all');
      final next = <String, dynamic>{};
      for (final t in analysisTypes) {
        if (result[t] != null) next[t] = result[t];
      }
      _analysesByApkId[apk.id!] = next;
      state = state.copyWith(analyses: next, runningAnalyzers: const {});
    } catch (e) {
      state = state.copyWith(
        runningAnalyzers: const {},
        analyzerErrors: {'all': e.toString()},
      );
    }
  }

  Future<void> _loadSavedAnalyses(String apkId) async {
    try {
      final saved = await _api.listApkAnalyses(apkId);
      _analysesByApkId[apkId] = Map<String, dynamic>.from(saved);
      if (state.selected?.id == apkId) {
        state = state.copyWith(analyses: _analysesByApkId[apkId]!);
      }
    } catch (_) {}
  }

  ApkAnalysis _buildAnalysisFromApk(ApkInfo apk) {
    return ApkAnalysis(
      apkPath: apk.path,
      packageName: apk.packageName,
      versionName: apk.versionName,
      versionCode: apk.versionCode,
      minSdk: apk.minSdk,
      targetSdk: apk.targetSdk,
      permissions: apk.permissions,
      activities: apk.activities.map((a) => a.name).toList(),
      services: apk.services.map((s) => s.name).toList(),
    );
  }
}

final apkProvider = StateNotifierProvider<ApkNotifier, ApkState>(
  (ref) => ApkNotifier(ref.watch(apiServiceProvider)),
);
