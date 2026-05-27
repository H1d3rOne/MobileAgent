import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../core/providers/device_provider.dart';
import '../../core/models/device_model.dart';

class DevicesPage extends ConsumerStatefulWidget {
  const DevicesPage({super.key});
  @override
  ConsumerState<DevicesPage> createState() => _DevicesPageState();
}

class _DevicesPageState extends ConsumerState<DevicesPage> {
  final _shellController = TextEditingController();
  String _shellOutput = '';
  bool _shellRunning = false;

  @override
  void dispose() {
    _shellController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(deviceProvider);
    final theme = Theme.of(context);

    return Scaffold(
      body: state.loading && state.devices.isEmpty
          ? const Center(child: CircularProgressIndicator())
          : Row(
              children: [
                // Device list
                SizedBox(
                  width: 320,
                  child: _buildDeviceList(context, state, theme),
                ),
                const VerticalDivider(width: 1),
                // Device detail / shell
                Expanded(
                  child: state.selectedDeviceInfo != null
                      ? _buildDeviceDetail(context, state, theme)
                      : Center(
                          child: Text('Select a device',
                              style: theme.textTheme.bodyLarge
                                  ?.copyWith(color: Colors.grey)),
                        ),
                ),
              ],
            ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showConnectDialog,
        icon: const Icon(Icons.add),
        label: const Text('Connect Wireless'),
      ),
    );
  }

  Widget _buildDeviceList(
      BuildContext context, DeviceListState state, ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              Text('Devices', style: theme.textTheme.headlineMedium),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.refresh),
                onPressed: () =>
                    ref.read(deviceProvider.notifier).refreshDevices(),
              ),
            ],
          ),
        ),
        if (state.error != null)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Text(state.error!,
                style: TextStyle(color: theme.colorScheme.error)),
          ),
        Expanded(
          child: state.devices.isEmpty
              ? Center(
                  child: Text('No devices', style: theme.textTheme.bodySmall))
              : ListView.builder(
                  itemCount: state.devices.length,
                  itemBuilder: (context, index) {
                    final device = state.devices[index];
                    final isSelected =
                        state.selectedDeviceInfo?.serial == device.serial;
                    return ListTile(
                      selected: isSelected,
                      leading: Icon(
                        device.state == DeviceState.online
                            ? Icons.phone_android
                            : Icons.phone_android_outlined,
                        color: device.state == DeviceState.online
                            ? Colors.green
                            : Colors.grey,
                      ),
                      title: Text(
                          device.model.isNotEmpty
                              ? device.model
                              : device.serial,
                          style: theme.textTheme.bodyMedium),
                      subtitle:
                          Text(device.serial, style: theme.textTheme.bodySmall),
                      trailing: Chip(
                        label: Text(device.state.name,
                            style: const TextStyle(fontSize: 10)),
                        backgroundColor: device.state == DeviceState.online
                            ? Colors.green.withValues(alpha: 0.2)
                            : Colors.grey.withValues(alpha: 0.2),
                      ),
                      onTap: () => ref
                          .read(deviceProvider.notifier)
                          .selectDevice(device.serial),
                    );
                  },
                ),
        ),
      ],
    );
  }

  Widget _buildDeviceDetail(
      BuildContext context, DeviceListState state, ThemeData theme) {
    final device = state.selectedDeviceInfo!;
    return DefaultTabController(
      length: 3,
      child: Column(
        children: [
          // Device header
          Container(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Icon(Icons.phone_android,
                    size: 48, color: theme.colorScheme.primary),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(device.model.isNotEmpty ? device.model : 'Unknown',
                          style: theme.textTheme.titleLarge),
                      Text(
                          'Android ${device.androidVersion.isNotEmpty ? device.androidVersion : "?"} (API ${device.sdkVersion.isNotEmpty ? device.sdkVersion : "?"})',
                          style: theme.textTheme.bodySmall),
                      Text(device.serial,
                          style: theme.textTheme.bodySmall
                              ?.copyWith(fontFamily: 'monospace')),
                    ],
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.screenshot),
                  tooltip: 'Screenshot',
                  onPressed: () =>
                      ref.read(deviceProvider.notifier).takeScreenshot(),
                ),
                IconButton(
                  icon: const Icon(Icons.delete_outline),
                  tooltip: 'Disconnect',
                  onPressed: () =>
                      ref.read(deviceProvider.notifier).selectDevice(''),
                ),
              ],
            ),
          ),
          const TabBar(tabs: [
            Tab(text: 'Info', icon: Icon(Icons.info_outline)),
            Tab(text: 'Shell', icon: Icon(Icons.terminal)),
            Tab(text: 'Apps', icon: Icon(Icons.apps)),
          ]),
          Expanded(
            child: TabBarView(
              children: [
                _buildInfoTab(device, theme),
                _buildShellTab(device, theme),
                _buildAppsTab(device, state, theme),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoTab(DeviceInfo device, ThemeData theme) {
    final info = <MapEntry<String, String>>[
      MapEntry('Model', device.model.isNotEmpty ? device.model : '-'),
      MapEntry('Brand', device.brand.isNotEmpty ? device.brand : '-'),
      MapEntry('Android',
          device.androidVersion.isNotEmpty ? device.androidVersion : '-'),
      MapEntry('SDK', device.sdkVersion.isNotEmpty ? device.sdkVersion : '-'),
      MapEntry('Serial', device.serial),
      MapEntry('IP', device.ipAddress.isNotEmpty ? device.ipAddress : '-'),
      MapEntry('Screen', '${device.screenWidth}×${device.screenHeight}'),
      MapEntry('Status', device.state.name),
    ];
    return ListView(
      padding: const EdgeInsets.all(16),
      children: info
          .map((e) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 4),
                child: Row(
                  children: [
                    SizedBox(
                        width: 100,
                        child: Text(e.key, style: theme.textTheme.bodySmall)),
                    Expanded(
                        child: Text(e.value,
                            style: theme.textTheme.bodyMedium
                                ?.copyWith(fontFamily: 'monospace'))),
                  ],
                ),
              ))
          .toList(),
    );
  }

  Widget _buildShellTab(DeviceInfo device, ThemeData theme) {
    return Column(
      children: [
        Expanded(
          child: Container(
            margin: const EdgeInsets.all(8),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.black,
              borderRadius: BorderRadius.circular(8),
            ),
            child: SingleChildScrollView(
              child: Text(
                _shellOutput.isEmpty
                    ? 'Shell output will appear here...'
                    : _shellOutput,
                style: const TextStyle(
                    fontFamily: 'monospace', color: Colors.green, fontSize: 13),
              ),
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.all(8),
          child: Row(
            children: [
              const Text('\$ ',
                  style: TextStyle(
                      fontFamily: 'monospace', fontWeight: FontWeight.bold)),
              Expanded(
                child: TextField(
                  controller: _shellController,
                  enabled: !_shellRunning,
                  decoration: const InputDecoration(
                    hintText: 'Enter command...',
                    isDense: true,
                    contentPadding:
                        EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  ),
                  onSubmitted: (_) => _executeShell(device.serial),
                ),
              ),
              const SizedBox(width: 8),
              IconButton(
                icon: _shellRunning
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.play_arrow),
                onPressed:
                    _shellRunning ? null : () => _executeShell(device.serial),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildAppsTab(
      DeviceInfo device, DeviceListState state, ThemeData theme) {
    if (state.packagesLoading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (state.packages.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Load installed packages'),
            const SizedBox(height: 8),
            ElevatedButton(
              onPressed: () =>
                  ref.read(deviceProvider.notifier).loadPackages(device.serial),
              child: const Text('Load Apps'),
            ),
          ],
        ),
      );
    }
    return ListView.builder(
      itemCount: state.packages.length,
      itemBuilder: (context, index) {
        final pkg = state.packages[index];
        return ListTile(
          leading: const Icon(Icons.android),
          title: Text(pkg.packageName, style: theme.textTheme.bodyMedium),
          subtitle:
              Text(pkg.versionName ?? '', style: theme.textTheme.bodySmall),
          trailing: IconButton(
            icon: const Icon(Icons.delete_outline, size: 18),
            onPressed: () => ref
                .read(deviceProvider.notifier)
                .uninstallPackage(pkg.packageName),
          ),
        );
      },
    );
  }

  Future<void> _executeShell(String serial) async {
    final cmd = _shellController.text.trim();
    if (cmd.isEmpty) return;
    _shellController.clear();
    setState(() {
      _shellRunning = true;
      _shellOutput += '\$ $cmd\n';
    });
    try {
      final output = await ref.read(deviceProvider.notifier).executeShell(cmd);
      setState(() {
        _shellOutput += '$output\n';
      });
    } catch (e) {
      setState(() {
        _shellOutput += 'Error: $e\n';
      });
    } finally {
      setState(() {
        _shellRunning = false;
      });
    }
  }

  void _showConnectDialog() {
    final addrController = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Connect Wireless Device'),
        content: TextField(
          controller: addrController,
          decoration: const InputDecoration(
            hintText: '192.168.1.100:5555',
            labelText: 'Address',
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () {
              final addr = addrController.text.trim();
              if (addr.isNotEmpty) {
                ref.read(deviceProvider.notifier).connectWireless(addr);
                Navigator.pop(ctx);
              }
            },
            child: const Text('Connect'),
          ),
        ],
      ),
    );
  }
}
