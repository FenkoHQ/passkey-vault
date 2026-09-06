import Foundation
import AuthenticationServices
import CoreFoundation

/// Shared vault, backed by the App Group container so the app and the credential
/// provider extension see the same data (the iOS equivalent of Android's
/// `ProviderVaultStore` SharedPreferences). Stored as JSON strings under the same
/// logical keys for cross-platform familiarity.
final class VaultStore {
    static let appGroup = "group.nz.fenko.passkeyvault"
    static let shared = VaultStore()

    private let defaults: UserDefaults

    private enum Key {
        static let passkeys = "passkeys"
        static let totp = "totp_entries"
        static let syncConfig = "sync_config"
        static let syncDevices = "sync_devices"
        static let customRelays = "custom_relays"
    }

    init(suiteName: String = VaultStore.appGroup) {
        // Falls back to .standard only so unit tests run outside an App Group.
        defaults = UserDefaults(suiteName: suiteName) ?? .standard
    }

    // MARK: Passkeys

    func loadPasskeys() -> [PasskeyRecord] {
        guard let raw = defaults.string(forKey: Key.passkeys),
              let data = raw.data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return [] }
        return array.compactMap(PasskeyRecord.fromJSON)
    }

    func savePasskeys(_ passkeys: [PasskeyRecord]) {
        let array = passkeys.map { $0.toJSON() }
        if let data = try? JSONSerialization.data(withJSONObject: array),
           let string = String(data: data, encoding: .utf8) {
            defaults.set(string, forKey: Key.passkeys)
        }
        updateCredentialIdentities(passkeys)
    }

    func findPasskey(credentialId: String) -> PasskeyRecord? {
        loadPasskeys().first { $0.credentialId == credentialId || $0.id == credentialId }
    }

    func upsert(_ passkey: PasskeyRecord) {
        var passkeys = loadPasskeys()
        if let idx = passkeys.firstIndex(where: {
            $0.id == passkey.id || $0.credentialId == passkey.credentialId
        }) {
            passkeys[idx] = passkey
        } else {
            passkeys.append(passkey)
        }
        savePasskeys(passkeys)
    }

    // MARK: TOTP

    func loadTOTP() -> [TOTPEntry] {
        guard let raw = defaults.string(forKey: Key.totp),
              let data = raw.data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return [] }
        return array.compactMap(TOTPEntry.fromJSON)
    }

    // MARK: Import (browser/Android backup JSON)

    /// Accepts a backup object `{ passkeys: [...], totpEntries: [...] }` or a bare
    /// array of passkeys. Returns the number of passkeys imported.
    @discardableResult
    func importBackup(_ data: Data) -> Int {
        guard let root = try? JSONSerialization.jsonObject(with: data) else { return 0 }

        var incomingPasskeys: [[String: Any]] = []
        var incomingTOTP: [[String: Any]] = []
        if let obj = root as? [String: Any] {
            incomingPasskeys = (obj["passkeys"] as? [[String: Any]]) ?? []
            incomingTOTP = (obj["totpEntries"] as? [[String: Any]])
                ?? (obj["totp"] as? [[String: Any]]) ?? []
        } else if let array = root as? [[String: Any]] {
            incomingPasskeys = array
        }

        var passkeys = loadPasskeys()
        var imported = 0
        for obj in incomingPasskeys {
            guard let record = PasskeyRecord.fromJSON(obj) else { continue }
            if let idx = passkeys.firstIndex(where: { $0.credentialId == record.credentialId }) {
                passkeys[idx] = record
            } else {
                passkeys.append(record)
            }
            imported += 1
        }
        savePasskeys(passkeys)

        if !incomingTOTP.isEmpty,
           let totpData = try? JSONSerialization.data(withJSONObject: incomingTOTP),
           let totpString = String(data: totpData, encoding: .utf8) {
            defaults.set(totpString, forKey: Key.totp)
        }
        return imported
    }

    // MARK: WebView bridge (snapshot in/out, mirrors Android's ProviderVaultStore)

    /// JSON string the web app's `loadVaultSnapshot()` consumes. Keys must match
    /// what app.ts reads: passkeys, totpEntries, syncConfig, syncDevices, customRelays.
    func snapshotJSON() -> String {
        let passkeys = defaults.string(forKey: Key.passkeys) ?? "[]"
        let totp = defaults.string(forKey: Key.totp) ?? "[]"
        let syncConfig = defaults.string(forKey: Key.syncConfig) ?? "{}"
        let syncDevices = defaults.string(forKey: Key.syncDevices) ?? "null"
        let customRelays = defaults.string(forKey: Key.customRelays) ?? "[]"
        return "{\"passkeys\":\(passkeys),\"totpEntries\":\(totp),\"syncConfig\":\(syncConfig),\"syncDevices\":\(syncDevices),\"customRelays\":\(customRelays)}"
    }

    /// Persists what the web app mirrors out, so the credential provider can read
    /// the same vault. Each argument is a JSON string (or nil to leave unchanged).
    func saveSnapshotFromWeb(passkeys: String?, totp: String?, syncConfig: String?,
                             syncDevices: String?, customRelays: String?) {
        var config = object(syncConfig ?? "{}")
        let oldConfig = object(defaults.string(forKey: Key.syncConfig) ?? "{}")
        var deletions: [String: [String: Any]] = [:]
        for item in (oldConfig["deletions"] as? [[String: Any]] ?? []) +
                    (config["deletions"] as? [[String: Any]] ?? []) {
            guard let kind = item["kind"] as? String, let id = item["id"] as? String,
                  let time = item["deletedAt"] as? Double,
                  time.isFinite, ["passkey", "totp"].contains(kind) else { continue }
            let key = kind + ":" + id
            if time > (deletions[key]?["deletedAt"] as? Double ?? -Double.infinity) {
                deletions[key] = item
            }
        }
        config["deletions"] = Array(deletions.values)
        config.removeValue(forKey: "syncSalt")
        // Save deletion history first, including when the WebView omits records.
        defaults.set(json(config), forKey: Key.syncConfig)
        defaults.set(mergeEntries(defaults.string(forKey: Key.passkeys) ?? "[]",
                                 passkeys ?? "[]", Array(deletions.values), "passkey"), forKey: Key.passkeys)
        defaults.set(mergeEntries(defaults.string(forKey: Key.totp) ?? "[]",
                                 totp ?? "[]", Array(deletions.values), "totp"), forKey: Key.totp)
        if let syncDevices { defaults.set(syncDevices, forKey: Key.syncDevices) }
        if let customRelays { defaults.set(customRelays, forKey: Key.customRelays) }
        updateCredentialIdentities()
    }

    func resetVault() {
        for key in [Key.passkeys, Key.totp, Key.syncConfig, Key.syncDevices, Key.customRelays] {
            defaults.removeObject(forKey: key)
        }
        updateCredentialIdentities([])
    }

    private func object(_ raw: String) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(raw.utf8))) as? [String: Any] ?? [:]
    }

    private func json(_ value: Any) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: value) else { return "null" }
        return String(decoding: data, as: UTF8.self)
    }

    // Same ASCII ordering as the JS and Java stores, without counter metadata.
    private func canonical(_ value: Any) -> String {
        if value is NSNull { return "n" }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "b1" : "b0" }
            let double = number.doubleValue == 0 ? 0.0 : number.doubleValue
            return "d" + String(format: "%016llx", double.bitPattern)
        }
        if let text = value as? String {
            return "s" + text.utf16.map { String(format: "%04x", $0) }.joined() + ";"
        }
        if let list = value as? [Any] { return "[" + list.map(canonical).joined() + "]" }
        guard let object = value as? [String: Any] else { return "n" }
        let keys = object.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
        return "{" + keys.map { canonical($0) + canonical(object[$0]!) }.joined() + "}"
    }

    private func recordOrder(_ record: [String: Any]) -> String {
        var value = record
        for key in ["counter", "syncSource", "syncTimestamp"] { value.removeValue(forKey: key) }
        return canonical(value)
    }

    private func revision(_ record: [String: Any]) -> Double {
        record["updatedAt"] as? Double ?? record["createdAt"] as? Double ?? 0
    }

    private func mergeEntries(_ local: String, _ incoming: String,
                              _ deletions: [[String: Any]], _ kind: String) -> String {
        var records: [String: [String: Any]] = [:]
        for raw in [local, incoming] {
            let list = (try? JSONSerialization.jsonObject(with: Data(raw.utf8))) as? [[String: Any]] ?? []
            for item in list {
                guard let id = item["id"] as? String ?? item["credentialId"] as? String else { continue }
                guard let current = records[id] else { records[id] = item; continue }
                let newer = revision(item) > revision(current) ||
                    (revision(item) == revision(current) && recordOrder(item) > recordOrder(current))
                var winner = newer ? item : current
                winner["counter"] = max(item["counter"] as? Int ?? 0, current["counter"] as? Int ?? 0)
                records[id] = winner
            }
        }
        for item in deletions {
            guard item["kind"] as? String == kind, let id = item["id"] as? String,
                  let record = records[id], let deletedAt = item["deletedAt"] as? Double else { continue }
            if revision(record) <= deletedAt { records.removeValue(forKey: id) }
        }
        return json(records.keys.sorted().compactMap { records[$0] })
    }

    // MARK: Credential identity registration (QuickType / matching)

    func updateCredentialIdentities(_ passkeys: [PasskeyRecord]? = nil) {
        let records = passkeys ?? loadPasskeys()
        let identities: [ASCredentialIdentity] = records.compactMap { record in
            guard let credID = Base64URL.decode(record.credentialId) else { return nil }
            let userHandle = record.userId.flatMap(Base64URL.decode) ?? Data()
            return ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: record.rpId,
                userName: record.userName.isEmpty ? record.rpId : record.userName,
                credentialID: credID,
                userHandle: userHandle
            )
        }
        ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities) { _, _ in }
    }
}
