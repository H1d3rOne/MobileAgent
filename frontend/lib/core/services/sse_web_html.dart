// Web-only SSE client: uses XMLHttpRequest with `onProgress` events to read
// `text/event-stream` chunks incrementally. Yields the cumulative `responseText`
// each time the browser delivers a chunk; the caller is responsible for
// computing deltas and parsing SSE events.
//
// This sidesteps dio's BrowserHttpClientAdapter which buffers the response and
// delivers it as a single string only when the connection completes — fine for
// short stub replies, but it would hide real-time LLM streaming UX.

import 'dart:async';
// ignore: deprecated_member_use, avoid_web_libraries_in_flutter
import 'dart:html' as html;

Stream<String> webSseStream({
  required String url,
  required Map<String, String> headers,
  required String body,
}) {
  final controller = StreamController<String>();
  late final html.HttpRequest xhr;
  xhr = html.HttpRequest()
    ..open('POST', url, async: true)
    ..responseType = 'text';
  headers.forEach((k, v) => xhr.setRequestHeader(k, v));

  xhr.onProgress.listen((_) {
    final txt = xhr.responseText ?? '';
    if (txt.isNotEmpty) controller.add(txt);
  });
  xhr.onLoad.listen((_) {
    final txt = xhr.responseText ?? '';
    if (txt.isNotEmpty) controller.add(txt);
    controller.close();
  });
  xhr.onError.listen((_) {
    controller.addError(StateError('XHR error (status ${xhr.status})'));
    controller.close();
  });
  xhr.onAbort.listen((_) {
    controller.close();
  });

  controller.onCancel = () {
    try {
      xhr.abort();
    } catch (_) {}
  };

  xhr.send(body);
  return controller.stream;
}
