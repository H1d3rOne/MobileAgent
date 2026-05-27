import 'package:flutter/foundation.dart' show kIsWeb, defaultTargetPlatform, TargetPlatform;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

class AppShell extends ConsumerWidget {
  final Widget child;
  const AppShell({super.key, required this.child});

  static bool get _showTerminalTab {
    if (kIsWeb) return false;
    return defaultTargetPlatform == TargetPlatform.android;
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final currentLocation = GoRouterState.of(context).matchedLocation;

    final destinations = <NavigationRailDestination>[
      const NavigationRailDestination(
        icon: Icon(Icons.chat_bubble_outline),
        selectedIcon: Icon(Icons.chat_bubble),
        label: Text('Chat'),
      ),
      const NavigationRailDestination(
        icon: Icon(Icons.phone_android_outlined),
        selectedIcon: Icon(Icons.phone_android),
        label: Text('Devices'),
      ),
      const NavigationRailDestination(
        icon: Icon(Icons.android_outlined),
        selectedIcon: Icon(Icons.android),
        label: Text('APK'),
      ),
      const NavigationRailDestination(
        icon: Icon(Icons.extension_outlined),
        selectedIcon: Icon(Icons.extension),
        label: Text('Skills'),
      ),
      const NavigationRailDestination(
        icon: Icon(Icons.memory_outlined),
        selectedIcon: Icon(Icons.memory),
        label: Text('Memory'),
      ),
      const NavigationRailDestination(
        icon: Icon(Icons.hub_outlined),
        selectedIcon: Icon(Icons.hub),
        label: Text('MCP'),
      ),
      if (_showTerminalTab)
        const NavigationRailDestination(
          icon: Icon(Icons.terminal_outlined),
          selectedIcon: Icon(Icons.terminal),
          label: Text('Terminal'),
        ),
      const NavigationRailDestination(
        icon: Icon(Icons.settings_outlined),
        selectedIcon: Icon(Icons.settings),
        label: Text('Settings'),
      ),
    ];

    return Scaffold(
      body: Row(
        children: [
          NavigationRail(
            selectedIndex: _selectedIndex(currentLocation),
            onDestinationSelected: (index) => _onTap(context, index),
            labelType: NavigationRailLabelType.all,
            leading: Padding(
              padding: const EdgeInsets.symmetric(vertical: 16),
              child: Column(
                children: [
                  Icon(Icons.android, size: 36, color: theme.colorScheme.primary),
                  const SizedBox(height: 4),
                  Text('MobileAgent', style: theme.textTheme.labelSmall),
                ],
              ),
            ),
            destinations: destinations,
          ),
          const VerticalDivider(width: 1),
          Expanded(child: child),
        ],
      ),
    );
  }

  int _selectedIndex(String location) {
    if (location.startsWith('/device')) return 1;
    if (location.startsWith('/apk')) return 2;
    if (location.startsWith('/skills')) return 3;
    if (location.startsWith('/memory')) return 4;
    if (location.startsWith('/mcp')) return 5;
    if (_showTerminalTab && location.startsWith('/terminal')) return 6;
    if (location.startsWith('/settings')) return _showTerminalTab ? 7 : 6;
    return 0;
  }

  void _onTap(BuildContext context, int index) {
    if (!_showTerminalTab) {
      switch (index) {
        case 0: context.go('/');
        case 1: context.go('/device');
        case 2: context.go('/apk');
        case 3: context.go('/skills');
        case 4: context.go('/memory');
        case 5: context.go('/mcp');
        case 6: context.go('/settings');
      }
      return;
    }
    switch (index) {
      case 0: context.go('/');
      case 1: context.go('/device');
      case 2: context.go('/apk');
      case 3: context.go('/skills');
      case 4: context.go('/memory');
      case 5: context.go('/mcp');
      case 6: context.go('/terminal');
      case 7: context.go('/settings');
    }
  }
}
