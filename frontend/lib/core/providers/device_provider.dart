import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/device_model.dart';
import '../services/api_service.dart';

class DeviceNotifier extends StateNotifier<DeviceListState> {
  final ApiService _api;
  Timer? _refreshTimer;
  
  DeviceNotifier(this._api) : super(const DeviceListState()) {
    refreshDevices();
    _refreshTimer = Timer.periodic(const Duration(seconds: 5), (_) => refreshDevices());
  }
  
  @override
  void dispose() { _refreshTimer?.cancel(); super.dispose(); }
  
  Future<void> refreshDevices() async {
    try {
      final devices = await _api.listDevices();
      state = state.copyWith(
        devices: devices.map((d) => DeviceInfo.fromJson(d)).toList(),
        loading: false,
        error: null,
      );
    } catch (e) {
      state = state.copyWith(loading: false, error: e.toString());
    }
  }
  
  Future<void> selectDevice(String serial) async {
    state = state.copyWith(selectedSerial: serial);
    await loadDeviceInfo(serial);
    await loadPackages(serial);
  }
  
  Future<void> loadDeviceInfo(String serial) async {
    try {
      final info = await _api.getDeviceInfo(serial);
      state = state.copyWith(selectedDeviceInfo: DeviceInfo.fromJson(info));
    } catch (e) {
      state = state.copyWith(error: e.toString());
    }
  }
  
  Future<void> loadPackages(String serial) async {
    state = state.copyWith(packagesLoading: true);
    try {
      final pkgs = await _api.listPackages(serial);
      final pkgList = (pkgs['packages'] as List?)?.cast<Map<String, dynamic>>() ?? [];
      state = state.copyWith(
        packages: pkgList.map((p) => PackageInfo.fromJson(p)).toList(),
        packagesLoading: false,
      );
    } catch (e) {
      state = state.copyWith(packagesLoading: false, error: e.toString());
    }
  }
  
  Future<String> executeShell(String command) async {
    final serial = state.selectedSerial;
    if (serial == null) return 'No device selected';
    try {
      state = state.copyWith(shellLoading: true);
      final output = await _api.executeShell(serial, command);
      final newHistory = [...state.shellHistory, ShellEntry(command: command, output: output, timestamp: DateTime.now())];
      state = state.copyWith(shellHistory: newHistory, shellLoading: false);
      return output;
    } catch (e) {
      state = state.copyWith(shellLoading: false, error: e.toString());
      return 'Error: $e';
    }
  }
  
  Future<String?> takeScreenshot() async {
    final serial = state.selectedSerial;
    if (serial == null) return null;
    try {
      return await _api.takeScreenshot(serial);
    } catch (e) {
      state = state.copyWith(error: e.toString());
      return null;
    }
  }
  
  Future<void> installApk(String apkPath) async {
    final serial = state.selectedSerial;
    if (serial == null) return;
    try {
      await _api.installApk(serial, apkPath);
      await loadPackages(serial);
    } catch (e) {
      state = state.copyWith(error: e.toString());
    }
  }
  
  Future<void> uninstallPackage(String packageName) async {
    final serial = state.selectedSerial;
    if (serial == null) return;
    try {
      await _api.executeShell(serial, 'pm uninstall $packageName');
      await loadPackages(serial);
    } catch (e) {
      state = state.copyWith(error: e.toString());
    }
  }

  Future<void> connectWireless(String address) async {
    final serial = state.selectedSerial;
    try {
      if (serial != null) {
        await _api.connectWireless(serial, address);
      }
      await refreshDevices();
    } catch (e) {
      state = state.copyWith(error: e.toString());
    }
  }
}

class ShellEntry {
  final String command;
  final String output;
  final DateTime timestamp;
  const ShellEntry({required this.command, required this.output, required this.timestamp});
}

class DeviceListState {
  final List<DeviceInfo> devices;
  final String? selectedSerial;
  final DeviceInfo? selectedDeviceInfo;
  final List<PackageInfo> packages;
  final List<ShellEntry> shellHistory;
  final bool loading;
  final bool packagesLoading;
  final bool shellLoading;
  final String? error;
  
  const DeviceListState({
    this.devices = const [],
    this.selectedSerial,
    this.selectedDeviceInfo,
    this.packages = const [],
    this.shellHistory = const [],
    this.loading = false,
    this.packagesLoading = false,
    this.shellLoading = false,
    this.error,
  });
  
  DeviceListState copyWith({
    List<DeviceInfo>? devices, String? selectedSerial, DeviceInfo? selectedDeviceInfo,
    List<PackageInfo>? packages, List<ShellEntry>? shellHistory,
    bool? loading, bool? packagesLoading, bool? shellLoading, String? error,
  }) => DeviceListState(
    devices: devices ?? this.devices, selectedSerial: selectedSerial ?? this.selectedSerial,
    selectedDeviceInfo: selectedDeviceInfo ?? this.selectedDeviceInfo,
    packages: packages ?? this.packages, shellHistory: shellHistory ?? this.shellHistory,
    loading: loading ?? this.loading, packagesLoading: packagesLoading ?? this.packagesLoading,
    shellLoading: shellLoading ?? this.shellLoading, error: error,
  );
}

final deviceProvider = StateNotifierProvider<DeviceNotifier, DeviceListState>((ref) {
  return DeviceNotifier(ref.watch(apiServiceProvider));
});
