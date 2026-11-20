import 'package:flutter/material.dart';
import 'package:firebase_core/firebase_core.dart';
import 'router.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp();
  runApp(MaterialApp.router(routerConfig: router));
}
