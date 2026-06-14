import Foundation
import AuthenticationServices

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
        if let passkeys { defaults.set(passkeys, forKey: Key.passkeys) }
        if let totp { defaults.set(totp, forKey: Key.totp) }
        if let syncConfig { defaults.set(syncConfig, forKey: Key.syncConfig) }
        if let syncDevices { defaults.set(syncDevices, forKey: Key.syncDevices) }
        if let customRelays { defaults.set(customRelays, forKey: Key.customRelays) }
        if passkeys != nil { updateCredentialIdentities() }
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
