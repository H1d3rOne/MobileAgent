import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'core/theme/app_theme.dart';
import 'features/chat/chat_page.dart';
import 'features/apk/apk_page.dart';
import 'features/devices/devices_page.dart';
import 'features/mcp/mcp_page.dart';
import 'features/memory/memory_page.dart';
import 'features/settings/settings_page.dart';
import 'features/skills/skills_page.dart';
import 'features/terminal/terminal_page.dart';
import 'shared/widgets/app_shell.dart';

final _router = GoRouter(
  routes: [
    ShellRoute(
      builder: (context, state, child) => AppShell(child: child),
      routes: [
        GoRoute(path: '/', builder: (_, __) => const ChatPage()),
        GoRoute(path: '/apk', builder: (_, __) => const ApkPage()),
        GoRoute(path: '/device', builder: (_, __) => const DevicesPage()),
        GoRoute(path: '/skills', builder: (_, __) => const SkillsPage()),
        GoRoute(path: '/memory', builder: (_, __) => const MemoryPage()),
        GoRoute(path: '/mcp', builder: (_, __) => const McpPage()),
        GoRoute(path: '/terminal', builder: (_, __) => const TerminalPage()),
        GoRoute(path: '/settings', builder: (_, __) => const SettingsPage()),
      ],
    ),
  ],
);

class MobileAgentApp extends ConsumerWidget {
  const MobileAgentApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final themeMode = ref.watch(themeProvider);

    return MaterialApp.router(
      title: 'MobileAgent',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: themeMode,
      routerConfig: _router,
    );
  }
}
