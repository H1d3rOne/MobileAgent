// Default (non-web) implementation: not used. The web variant is loaded via
// conditional import in api_service.dart.
import 'dart:async';

Stream<String> webSseStream({
  required String url,
  required Map<String, String> headers,
  required String body,
}) {
  throw UnsupportedError('webSseStream is only available on Flutter Web');
}
