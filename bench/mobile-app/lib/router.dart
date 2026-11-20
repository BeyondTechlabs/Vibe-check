import 'package:go_router/go_router.dart';
import 'screens.dart';

final router = GoRouter(
  initialLocation: '/',
  routes: [
    GoRoute(path: '/', builder: (c, s) => const HomeScreen()),
    GoRoute(path: '/login', builder: (c, s) => const LoginScreen()),
    // Opened from staff emails: trailmate://app/admin/rewards
    GoRoute(path: '/admin/rewards', builder: (c, s) => const RewardsAdminScreen()),
  ],
);
