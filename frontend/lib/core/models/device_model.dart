class DeviceInfo {
  final String serial;
  final String model;
  final String brand;
  final String androidVersion;
  final String sdkVersion;
  final String cpuAbi;
  final int screenWidth;
  final int screenHeight;
  final int dpi;
  final String ipAddress;
  final DeviceState state;
  
  const DeviceInfo({
    required this.serial,
    required this.model,
    this.brand = '',
    this.androidVersion = '',
    this.sdkVersion = '',
    this.cpuAbi = '',
    this.screenWidth = 0,
    this.screenHeight = 0,
    this.dpi = 0,
    this.ipAddress = '',
    this.state = DeviceState.online,
  });
  
  factory DeviceInfo.fromJson(Map<String, dynamic> json) => DeviceInfo(
    serial: json['serial'] ?? '',
    model: json['model'] ?? '',
    brand: json['brand'] ?? '',
    androidVersion: json['android_version'] ?? '',
    sdkVersion: json['sdk_version'] ?? '',
    cpuAbi: json['cpu_abi'] ?? '',
    screenWidth: json['screen_width'] ?? 0,
    screenHeight: json['screen_height'] ?? 0,
    dpi: json['dpi'] ?? 0,
    ipAddress: json['ip_address'] ?? '',
    state: DeviceState.values.byName(json['state'] ?? 'online'),
  );
  
  String get displayName => '$brand $model'.trim();
}

enum DeviceState { online, offline, unauthorized, recovery }

class PackageInfo {
  final String packageName;
  final String? versionName;
  final int? versionCode;
  final String? apkPath;
  final bool isSystem;
  
  const PackageInfo({
    required this.packageName,
    this.versionName,
    this.versionCode,
    this.apkPath,
    this.isSystem = false,
  });
  
  factory PackageInfo.fromJson(Map<String, dynamic> json) => PackageInfo(
    packageName: json['package_name'] ?? '',
    versionName: json['version_name'],
    versionCode: json['version_code'],
    apkPath: json['apk_path'],
    isSystem: json['is_system'] ?? false,
  );
}

class ShellResult {
  final String output;
  final int exitCode;
  final Duration duration;
  
  const ShellResult({required this.output, this.exitCode = 0, this.duration = Duration.zero});
}
