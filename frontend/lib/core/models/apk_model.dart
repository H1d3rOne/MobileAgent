class ApkInfo {
  final String? id;
  final String path;
  final String packageName;
  final String versionName;
  final int versionCode;
  final int minSdk;
  final int targetSdk;
  final String? icon;
  final String? label;
  final int fileSize;
  final int? apkCount;
  final List<String> permissions;
  final List<ActivityInfo> activities;
  final List<ServiceInfo> services;
  final List<String> nativeLibs;
  final String? decompiledPath;
  final String? decompileTool;
  final String? status;

  const ApkInfo({
    this.id,
    required this.path,
    required this.packageName,
    this.versionName = '',
    this.versionCode = 0,
    this.minSdk = 0,
    this.targetSdk = 0,
    this.icon,
    this.label,
    this.fileSize = 0,
    this.apkCount,
    this.permissions = const [],
    this.activities = const [],
    this.services = const [],
    this.nativeLibs = const [],
    this.decompiledPath,
    this.decompileTool,
    this.status,
  });

  ApkInfo copyWith({
    String? decompiledPath,
    String? decompileTool,
    String? status,
  }) =>
      ApkInfo(
        id: id,
        path: path,
        packageName: packageName,
        versionName: versionName,
        versionCode: versionCode,
        minSdk: minSdk,
        targetSdk: targetSdk,
        icon: icon,
        label: label,
        fileSize: fileSize,
        apkCount: apkCount,
        permissions: permissions,
        activities: activities,
        services: services,
        nativeLibs: nativeLibs,
        decompiledPath: decompiledPath ?? this.decompiledPath,
        decompileTool: decompileTool ?? this.decompileTool,
        status: status ?? this.status,
      );

  factory ApkInfo.fromJson(Map<String, dynamic> json) => ApkInfo(
    id: json['id']?.toString(),
    path: json['file_path'] ?? json['path'] ?? '',
    packageName: json['package_name'] ?? '',
    versionName: json['version_name'] ?? '',
    versionCode: json['version_code'] ?? 0,
    minSdk: json['min_sdk'] ?? 0,
    targetSdk: json['target_sdk'] ?? 0,
    icon: json['icon'],
    label: json['label'],
    fileSize: json['file_size'] ?? 0,
    apkCount: json['apk_count'],
    permissions: (json['permissions'] is List)
        ? (json['permissions'] as List).cast<String>()
        : (json['permissions'] is String && (json['permissions'] as String).isNotEmpty)
            ? (json['permissions'] as String).split(',').where((e) => e.isNotEmpty).toList()
            : [],
    activities: (json['activities'] is List)
        ? (json['activities'] as List)
            .map((a) => a is Map<String, dynamic>
                ? ActivityInfo.fromJson(a)
                : ActivityInfo(name: a.toString()))
            .toList()
        : (json['activities'] is String && (json['activities'] as String).isNotEmpty)
            ? (json['activities'] as String)
                .split(',')
                .where((e) => e.isNotEmpty)
                .map((n) => ActivityInfo(name: n))
                .toList()
            : [],
    services: (json['services'] as List?)
            ?.map((s) => s is Map<String, dynamic>
                ? ServiceInfo.fromJson(s)
                : ServiceInfo(name: s.toString()))
            .toList() ??
        [],
    nativeLibs: (json['native_libs'] as List?)?.cast<String>() ?? [],
    decompiledPath: json['decompiled_path'],
    decompileTool: json['decompiled_tool'],
    status: json['status'],
  );

  String get displayName => label ?? packageName;
  String get fileSizeFormatted {
    if (fileSize < 1024) return '$fileSize B';
    if (fileSize < 1048576) return '${(fileSize / 1024).toStringAsFixed(1)} KB';
    return '${(fileSize / 1048576).toStringAsFixed(1)} MB';
  }
}

class ActivityInfo {
  final String name;
  final bool isLauncher;
  final Map<String, dynamic>? intentFilters;
  
  const ActivityInfo({required this.name, this.isLauncher = false, this.intentFilters});
  factory ActivityInfo.fromJson(Map<String, dynamic> json) => ActivityInfo(
    name: json['name'] ?? '', isLauncher: json['is_launcher'] ?? false,
    intentFilters: json['intent_filters'],
  );
}

class ServiceInfo {
  final String name;
  final bool isExported;
  final bool isRunning;
  
  const ServiceInfo({required this.name, this.isExported = false, this.isRunning = false});
  factory ServiceInfo.fromJson(Map<String, dynamic> json) => ServiceInfo(
    name: json['name'] ?? '', isExported: json['is_exported'] ?? false,
    isRunning: json['is_running'] ?? false,
  );
}

class FileNode {
  final String name;
  final String path;
  final bool isDirectory;
  final List<FileNode> children;
  final int? size;
  final DateTime? modified;
  
  const FileNode({
    required this.name,
    required this.path,
    this.isDirectory = false,
    this.children = const [],
    this.size,
    this.modified,
  });
  
  factory FileNode.fromJson(Map<String, dynamic> json) => FileNode(
    name: json['name'] ?? '', path: json['path'] ?? '',
    isDirectory: json['is_directory'] ?? false,
    children: (json['children'] as List?)?.map((c) => FileNode.fromJson(c)).toList() ?? [],
    size: json['size'], modified: json['modified'] != null ? DateTime.tryParse(json['modified']) : null,
  );
}

enum DecompileMode { apktool, jadx }

class ApkAnalysis {
  final String apkPath;
  final String packageName;
  final String versionName;
  final int versionCode;
  final int minSdk;
  final int targetSdk;
  final List<String> permissions;
  final List<String> activities;
  final List<String> services;
  final Map<String, dynamic>? metadata;
  final String? certificateInfo;
  final String? decompiledPath;
  
  const ApkAnalysis({
    required this.apkPath,
    required this.packageName,
    required this.versionName,
    required this.versionCode,
    required this.minSdk,
    required this.targetSdk,
    this.permissions = const [],
    this.activities = const [],
    this.services = const [],
    this.metadata,
    this.certificateInfo,
    this.decompiledPath,
  });
  
  factory ApkAnalysis.fromJson(Map<String, dynamic> json) => ApkAnalysis(
    apkPath: json['apk_path'] ?? '',
    packageName: json['package_name'] ?? '',
    versionName: json['version_name'] ?? '',
    versionCode: json['version_code'] ?? 0,
    minSdk: json['min_sdk'] ?? 0,
    targetSdk: json['target_sdk'] ?? 0,
    permissions: List<String>.from(json['permissions'] ?? []),
    activities: List<String>.from(json['activities'] ?? []),
    services: List<String>.from(json['services'] ?? []),
    metadata: json['metadata'],
    certificateInfo: json['certificate_info'],
    decompiledPath: json['decompiled_path'],
  );
}

enum BuildStatus { idle, building, success, error }

class ApkBuildResult {
  final bool success;
  final String? outputApk;
  final String? error;
  final Duration? duration;
  
  const ApkBuildResult({required this.success, this.outputApk, this.error, this.duration});
}
