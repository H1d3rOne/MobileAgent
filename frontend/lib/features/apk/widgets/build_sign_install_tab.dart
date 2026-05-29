import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/providers/apk_provider.dart';
import '../../../core/services/api_service.dart';
import 'result_panel.dart';

class BuildTab extends ConsumerStatefulWidget {
  const BuildTab({super.key});

  @override
  ConsumerState<BuildTab> createState() => _BuildTabState();
}

class _BuildTabState extends ConsumerState<BuildTab> {
  final _pathController = TextEditingController();
  bool _running = false;
  String? _result;

  @override
  void dispose() {
    _pathController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final apk = ref.watch(apkProvider).selected!;
    final decompiledPath = apk.decompiledPath ?? '';
    if (_pathController.text.isEmpty && decompiledPath.isNotEmpty) {
      _pathController.text = decompiledPath;
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(children: [
            Expanded(child: TextField(
              controller: _pathController,
              decoration: const InputDecoration(
                labelText: 'Decompiled project path',
                hintText: '/path/to/decompiled/project',
                border: OutlineInputBorder(), isDense: true,
                contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              ),
              style: const TextStyle(fontSize: 13),
            )),
            const SizedBox(width: 8),
            FilledButton.icon(
              onPressed: _running ? null : _run,
              icon: _running
                  ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                  : const Icon(Icons.build_outlined, size: 16),
              label: Text(_running ? 'Building...' : 'Build'),
            ),
          ]),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: ResultPanel(
              content: _result,
              isRunning: _running,
              isError: _result?.startsWith('Error') ?? false,
              emptyHint: 'Rebuild a decompiled APK project with apktool',
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _run() async {
    final path = _pathController.text.trim();
    if (path.isEmpty) return;
    setState(() { _running = true; _result = null; });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.buildApk(path);
      setState(() { _result = 'Built: ${res['output_path'] ?? res.toString()}'; _running = false; });
    } catch (e) {
      setState(() { _result = 'Error: $e'; _running = false; });
    }
  }
}

class SignTab extends ConsumerStatefulWidget {
  const SignTab({super.key});

  @override
  ConsumerState<SignTab> createState() => _SignTabState();
}

class _SignTabState extends ConsumerState<SignTab> {
  final _pathController = TextEditingController();
  final _keystoreController = TextEditingController();
  final _aliasController = TextEditingController();
  bool _running = false;
  String? _result;

  @override
  void dispose() {
    _pathController.dispose();
    _keystoreController.dispose();
    _aliasController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final apk = ref.watch(apkProvider).selected!;
    if (_pathController.text.isEmpty) {
      _pathController.text = apk.path;
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Column(children: [
            TextField(
              controller: _pathController,
              decoration: const InputDecoration(
                labelText: 'APK path',
                border: OutlineInputBorder(), isDense: true,
                contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              ),
              style: const TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 8),
            Row(children: [
              Expanded(child: TextField(
                controller: _keystoreController,
                decoration: const InputDecoration(
                  labelText: 'Keystore (optional)',
                  hintText: 'Leave empty for debug key',
                  border: OutlineInputBorder(), isDense: true,
                  contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                ),
                style: const TextStyle(fontSize: 13),
              )),
              const SizedBox(width: 8),
              Expanded(child: TextField(
                controller: _aliasController,
                decoration: const InputDecoration(
                  labelText: 'Key alias (optional)',
                  border: OutlineInputBorder(), isDense: true,
                  contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                ),
                style: const TextStyle(fontSize: 13),
              )),
              const SizedBox(width: 8),
              FilledButton.icon(
                onPressed: _running ? null : _run,
                icon: _running
                    ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.key, size: 16),
                label: Text(_running ? 'Signing...' : 'Sign'),
              ),
            ]),
          ]),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: ResultPanel(
              content: _result,
              isRunning: _running,
              isError: _result?.startsWith('Error') ?? false,
              emptyHint: 'Sign an APK with a keystore (or debug key)',
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _run() async {
    final path = _pathController.text.trim();
    if (path.isEmpty) return;
    setState(() { _running = true; _result = null; });
    try {
      final api = ref.read(apiServiceProvider);
      final res = await api.signApk(
        path,
        keystorePath: _keystoreController.text.trim().isEmpty ? null : _keystoreController.text.trim(),
        keyAlias: _aliasController.text.trim().isEmpty ? null : _aliasController.text.trim(),
      );
      setState(() { _result = 'Signed: ${res['output_path'] ?? res.toString()}'; _running = false; });
    } catch (e) {
      setState(() { _result = 'Error: $e'; _running = false; });
    }
  }
}

class InstallTab extends ConsumerStatefulWidget {
  const InstallTab({super.key});

  @override
  ConsumerState<InstallTab> createState() => _InstallTabState();
}

class _InstallTabState extends ConsumerState<InstallTab> {
  final _serialController = TextEditingController();
  bool _running = false;
  String? _result;

  @override
  void dispose() {
    _serialController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final apk = ref.watch(apkProvider).selected!;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Row(children: [
            Expanded(child: TextField(
              controller: _serialController,
              decoration: const InputDecoration(
                labelText: 'Device serial (optional)',
                hintText: 'Leave empty for default device',
                border: OutlineInputBorder(), isDense: true,
                contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              ),
              style: const TextStyle(fontSize: 13),
            )),
            const SizedBox(width: 8),
            FilledButton.icon(
              onPressed: _running ? null : () => _run(apk.path),
              icon: _running
                  ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                  : const Icon(Icons.install_mobile, size: 16),
              label: Text(_running ? 'Installing...' : 'Install'),
            ),
          ]),
        ),
        const Divider(height: 1),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: ResultPanel(
              content: _result,
              isRunning: _running,
              isError: _result?.startsWith('Error') ?? false,
              emptyHint: 'Install the APK to a connected device via adb',
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _run(String apkPath) async {
    setState(() { _running = true; _result = null; });
    try {
      final api = ref.read(apiServiceProvider);
      final serial = _serialController.text.trim();
      final res = await api.installApk(serial, apkPath);
      setState(() { _result = 'Installed: ${res['output'] ?? 'success'}'; _running = false; });
    } catch (e) {
      setState(() { _result = 'Error: $e'; _running = false; });
    }
  }
}
