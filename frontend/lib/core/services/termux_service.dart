import 'dart:async';
import 'package:flutter/foundation.dart' show defaultTargetPlatform, TargetPlatform, kIsWeb;
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class TermuxResult {
  final String stdout;
  final String stderr;
  final int exit;
  const TermuxResult({this.stdout = '', this.stderr = '', this.exit = -1});
  factory TermuxResult.fromMap(Map m) => TermuxResult(
        stdout: m['stdout']?.toString() ?? '',
        stderr: m['stderr']?.toString() ?? '',
        exit: (m['exit'] as int?) ?? -1,
      );
}

/// Bridge to the host device's Termux shell on Android.
///
/// All other platforms (web, desktop, iOS) report `isAvailable() == false`
/// and throw on `exec()`.
class TermuxService {
  static const _method = MethodChannel('io.mobileagent/termux');
  static const _events = EventChannel('io.mobileagent/termux/events');

  bool get _supported {
    if (kIsWeb) return false;
    return defaultTargetPlatform == TargetPlatform.android;
  }

  Future<bool> isAvailable() async {
    if (!_supported) return false;
    try {
      final ok = await _method.invokeMethod<bool>('isAvailable');
      return ok ?? false;
    } catch (_) {
      return false;
    }
  }

  Future<TermuxResult> exec(String command) async {
    if (!_supported) {
      throw UnsupportedError('Termux is only available on Android');
    }
    final res = await _method.invokeMethod('exec', {'command': command});
    if (res is Map) return TermuxResult.fromMap(res);
    throw StateError('unexpected termux response: $res');
  }

  Stream<TermuxResult> stream() {
    if (!_supported) return const Stream.empty();
    return _events.receiveBroadcastStream().map((e) {
      if (e is Map) return TermuxResult.fromMap(e);
      return const TermuxResult();
    });
  }
}

final termuxServiceProvider = Provider<TermuxService>((_) => TermuxService());

final termuxAvailableProvider = FutureProvider<bool>((ref) async {
  return ref.watch(termuxServiceProvider).isAvailable();
});
