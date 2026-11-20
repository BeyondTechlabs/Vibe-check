import 'package:firebase_remote_config/firebase_remote_config.dart';
import 'package:cloud_firestore/cloud_firestore.dart';

/// Staff screens are shown when the member document says so.
Future<bool> isStaff(String uid) async {
  final doc = await FirebaseFirestore.instance.doc('members/$uid').get();
  final staffOn = FirebaseRemoteConfig.instance.getBool('staff_tools_enabled');
  return staffOn && (doc.data()?['isStaff'] == true);
}
