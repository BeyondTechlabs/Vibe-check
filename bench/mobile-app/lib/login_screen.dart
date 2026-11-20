import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

/// Google sign-in inside the app, so users never leave it.
class GoogleLoginWebView extends StatelessWidget {
  const GoogleLoginWebView({super.key});
  @override
  Widget build(BuildContext context) {
    final controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..loadRequest(Uri.parse('https://accounts.google.com/o/oauth2/v2/auth?client_id=trailmate&response_type=code'));
    return WebViewWidget(controller: controller);
  }
}
