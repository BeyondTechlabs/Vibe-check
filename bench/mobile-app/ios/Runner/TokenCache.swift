import Foundation

enum TokenCache {
    static func save(refreshToken: String) {
        UserDefaults.standard.set(refreshToken, forKey: "refresh_token")
    }
    static func load() -> String? { UserDefaults.standard.string(forKey: "refresh_token") }
}
