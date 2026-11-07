import Foundation

struct LegacyWebSnapshot {
    static let keys = ["passkeys", "totp_entries", "sync_config", "sync_devices", "custom_relays", "sync_deletions"]
    let values: [String: String]
    private static let maxBytes = 16 * 1024 * 1024

    init(_ values: [String: String]) throws {
        guard values.keys.allSatisfy(Self.keys.contains),
              values.values.reduce(0, { $0 + $1.utf8.count }) <= Self.maxBytes else { throw VaultError.invalidData }
        for (key, raw) in values {
            let value = try JSONSerialization.jsonObject(with: Data(raw.utf8), options: [.fragmentsAllowed])
            switch key {
            case "passkeys":
                guard let entries = value as? [[String: Any]], entries.allSatisfy({ PasskeyRecord.fromJSON($0) != nil }) else {
                    throw VaultError.invalidData
                }
            case "totp_entries":
                guard let entries = value as? [[String: Any]], entries.allSatisfy({ TOTPEntry.fromJSON($0) != nil }) else {
                    throw VaultError.invalidData
                }
            case "sync_config":
                guard value is [String: Any] else { throw VaultError.invalidData }
            case "sync_devices":
                guard value is [String: Any] || value is NSNull else { throw VaultError.invalidData }
            case "custom_relays":
                guard value is [String] else { throw VaultError.invalidData }
            case "sync_deletions":
                guard let entries = value as? [[String: Any]], entries.allSatisfy({ entry in
                    guard let kind = entry["kind"] as? String, let time = entry["deletedAt"] as? Double else { return false }
                    return ["passkey", "totp"].contains(kind) && entry["id"] is String && time.isFinite
                }) else { throw VaultError.invalidData }
            default: throw VaultError.invalidData
            }
        }
        self.values = values
    }
}
