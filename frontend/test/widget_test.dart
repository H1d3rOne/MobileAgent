import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:mobile_agent/app.dart';
import 'package:mobile_agent/core/providers/chat_provider.dart';

class _TestChatNotifier extends ChatNotifier {
  _TestChatNotifier(super.ref);

  @override
  Future<void> loadSessions() async {}
}

void main() {
  testWidgets('app renders shell', (WidgetTester tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          chatProvider.overrideWith(_TestChatNotifier.new),
        ],
        child: const MobileAgentApp(),
      ),
    );
    await tester.pump();

    expect(find.text('MobileAgent'), findsOneWidget);
  });
}
