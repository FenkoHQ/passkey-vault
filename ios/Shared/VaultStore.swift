import Foundation
import AuthenticationServices
import CoreFoundation
import LocalAuthentication

// Domain operations share one encrypted transaction across the app and AutoFill provider.
final class VaultStore {
    static let appGroup = "group.nz.fenko.passkeyvault"
    static let shared = VaultStore()

    private let archive: VaultArchive
    private let legacy: UserDefaults?

    private enum Key {
        static let passkeys = "passkeys"
        static let totp = "totp_entries"
        static let syncConfig = "sync_config"
        static let syncDevices = "sync_devices"
        static let customRelays = "custom_relays"
        static let migrated = "legacy_migrated"
        static let legacyKeys = [passkeys, totp, syncConfig, syncDevices, customRelays]
    }

    private init() {
        #if LOCAL_DEVICE_TEST
        let container = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        legacy = nil
        #else
        let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup)
        legacy = UserDefaults(suiteName: Self.appGroup)
        #endif
        archive = VaultArchive(directory: container?.appendingPathComponent("EncryptedVault", isDirectory: true))
    }

    init(archive: VaultArchive, legacy: UserDefaults? = nil) {
        self.archive = archive
        self.legacy = legacy
    }

    func unlock(context: LAContext) throws {
        let key = try DeviceKeyStore.load(context: context, creation: archive.exists ? .forbidden : .allowed)
        try archive.unlock(key: key)
        do {
            try migrateLegacy()
        } catch {
            archive.lock()
            throw error
        }
    }

    func lock() {
        archive.lock()
    }

    func migrateLegacy() throws {
        guard let legacy else { return }
        try archive.transaction { values in
            if values[Key.migrated] == nil {
                var source: [String: String] = [:]
                for key in Key.legacyKeys {
                    guard let raw = legacy.string(forKey: key) else { continue }
                    let decoded = try JSONSerialization.jsonObject(with: Data(raw.utf8), options: [.fragmentsAllowed])
                    if key == Key.passkeys || key == Key.totp {
                        guard decoded is [[String: Any]] else { throw VaultError.invalidData }
                    }
                    source[key] = raw
                }
                let config = mergeConfig(object(source[Key.syncConfig] ?? "{}"),
                                         object(values[Key.syncConfig] ?? "{}"))
                let deletions = config["deletions"] as? [[String: Any]] ?? []
                for (key, kind) in [(Key.passkeys, "passkey"), (Key.totp, "totp")] {
                    _ = try records(values[key])
                    values[key] = mergeEntries(values[key] ?? "[]", source[key] ?? "[]", deletions, kind)
                }
                values[Key.syncConfig] = try encode(config)
                for key in [Key.syncDevices, Key.customRelays] where values[key] == nil {
                    values[key] = source[key]
                }
                values[Key.migrated] = "1"
            }
        }
        // Remove legacy data only after the encrypted transaction is durable.
        for key in Key.legacyKeys { legacy.removeObject(forKey: key) }
        legacy.synchronize()
    }

    func loadPasskeys() throws -> [PasskeyRecord] {
        try records(archive.read()[Key.passkeys]).compactMap(PasskeyRecord.fromJSON)
    }

    func savePasskeys(_ passkeys: [PasskeyRecord]) throws {
        try archive.transaction { values in
            values[Key.passkeys] = try encode(passkeys.map { $0.toJSON() })
        }
        updateCredentialIdentities(passkeys)
    }

    func findPasskey(credentialId: String) throws -> PasskeyRecord? {
        try loadPasskeys().first { $0.credentialId == credentialId || $0.id == credentialId }
    }

    func upsert(_ passkey: PasskeyRecord) throws {
        try archive.transaction { values in
            var records = try self.records(values[Key.passkeys])
            if let index = records.firstIndex(where: {
                ($0["id"] as? String) == passkey.id || ($0["credentialId"] as? String) == passkey.credentialId
            }) {
                records[index] = passkey.toJSON()
            } else {
                records.append(passkey.toJSON())
            }
            values[Key.passkeys] = try encode(records)
        }
        updateCredentialIdentities(try loadPasskeys())
    }

    func loadTOTP() throws -> [TOTPEntry] {
        try records(archive.read()[Key.totp]).compactMap(TOTPEntry.fromJSON)
    }

    @discardableResult
    func importBackup(_ data: Data) throws -> Int {
        let parsed = try JSONSerialization.jsonObject(with: data)
        let payload: [String: Any]
        if let array = parsed as? [[String: Any]] {
            payload = ["passkeys": array]
        } else if let object = parsed as? [String: Any],
                  object["passkeys"] is [[String: Any]] || object["totpEntries"] is [[String: Any]] {
            payload = object
        } else {
            throw VaultError.invalidData
        }
        let passkeys = payload["passkeys"] as? [[String: Any]] ?? []
        guard passkeys.allSatisfy({ PasskeyRecord.fromJSON($0) != nil }) else { throw VaultError.invalidData }
        let totp = payload["totpEntries"] as? [[String: Any]] ?? []
        guard totp.allSatisfy({ TOTPEntry.fromJSON($0) != nil }) else { throw VaultError.invalidData }
        // Import credentials, leaving this device's sync identity unchanged.
        try saveSnapshotFromWeb(passkeys: encode(passkeys), totp: encode(totp), syncConfig: nil,
                                syncDevices: nil, customRelays: nil)
        return passkeys.count + totp.count
    }

    func snapshotJSON() throws -> String {
        let values = try archive.read()
        let fields = ["passkeys": values[Key.passkeys] ?? "[]",
                      "totpEntries": values[Key.totp] ?? "[]",
                      "syncConfig": values[Key.syncConfig] ?? "{}",
                      "syncDevices": values[Key.syncDevices] ?? "null",
                      "customRelays": values[Key.customRelays] ?? "[]"]
        var result: [String: Any] = [:]
        for (key, raw) in fields {
            result[key] = try JSONSerialization.jsonObject(with: Data(raw.utf8), options: [.fragmentsAllowed])
        }
        return try encode(result)
    }

    func saveSnapshotFromWeb(passkeys: String?, totp: String?, syncConfig: String?,
                             syncDevices: String?, customRelays: String?) throws {
        if let passkeys { _ = try records(passkeys) }
        if let totp { _ = try records(totp) }
        try archive.transaction { values in
            let config = mergeConfig(object(values[Key.syncConfig] ?? "{}"), object(syncConfig ?? "{}"))
            let deletions = config["deletions"] as? [[String: Any]] ?? []
            values[Key.syncConfig] = try encode(config)
            values[Key.passkeys] = mergeEntries(values[Key.passkeys] ?? "[]", passkeys ?? "[]",
                                                deletions, "passkey")
            values[Key.totp] = mergeEntries(values[Key.totp] ?? "[]", totp ?? "[]",
                                            deletions, "totp")
            if let syncDevices { values[Key.syncDevices] = syncDevices }
            if let customRelays { values[Key.customRelays] = customRelays }
        }
        updateCredentialIdentities(try loadPasskeys())
    }

    func resetVault() throws {
        try archive.transaction { values in
            values = [Key.migrated: "1"]
        }
        updateCredentialIdentities([])
    }

    func items(at date: Date = Date()) throws -> [VaultItem] {
        let passkeys = try loadPasskeys().map {
            VaultItem(id: $0.id, kind: .passkey, title: $0.rpId, account: $0.userName, code: nil)
        }
        let codes = try loadTOTP().map { entry in
            let valid = [6, 8].contains(entry.digits) && entry.period > 0
            return VaultItem(id: entry.id, kind: .totp,
                             title: entry.issuer.isEmpty ? "2FA code" : entry.issuer,
                             account: entry.account, code: valid ? TOTP.code(for: entry, at: date) : nil)
        }
        return (passkeys + codes).sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
    }

    func exportBackup(password: String) throws -> Data {
        try VaultBackup.encrypt(Data(snapshotJSON().utf8), password: password)
    }

    func importFile(_ url: URL, password: String) throws -> Int {
        try importBackup(VaultBackup.decrypt(VaultBackup.read(url), password: password))
    }

    func assertion(credentialID: Data, rpId: String, clientHash: Data) throws -> VaultAssertion {
        guard clientHash.count == 32, !rpId.isEmpty else { throw VaultError.invalidData }
        return try archive.transaction { values in
            var entries = try records(values[Key.passkeys])
            guard let index = entries.firstIndex(where: {
                guard let record = PasskeyRecord.fromJSON($0) else { return false }
                return Base64URL.decode(record.credentialId) == credentialID && record.rpId == rpId
            }), var record = PasskeyRecord.fromJSON(entries[index]),
                  record.counter >= 0, record.counter < UInt32.max else { throw VaultError.invalidData }
            record.counter += 1
            let authData = WebAuthn.authenticatorData(rpId: rpId, credentialId: nil, cosePublicKey: nil,
                                                     includeAttestedCredentialData: false,
                                                     counter: record.counter, backupFlags: record.backupFlagBits)
            let signature = try WebAuthn.assertionSignature(privateKeyPKCS8B64: record.privateKey,
                                                            authenticatorData: authData,
                                                            clientDataHash: clientHash)
            entries[index] = record.toJSON()
            values[Key.passkeys] = try encode(entries)
            return VaultAssertion(userHandle: record.userId.flatMap(Base64URL.decode) ?? Data(),
                                  authenticatorData: authData, signature: signature)
        }
    }

    func credentials(rpId: String, allowed: [Data]) throws -> [ProviderCredential] {
        try loadPasskeys().compactMap { record in
            guard record.rpId == rpId, let id = Base64URL.decode(record.credentialId),
                  allowed.isEmpty || allowed.contains(id) else { return nil }
            return ProviderCredential(id: id, account: record.userName.isEmpty ? record.rpId : record.userName)
        }.sorted { $0.account.localizedStandardCompare($1.account) == .orderedAscending }
    }

    func register(rpId: String, userName: String, userHandle: Data,
                  excluded: [Data]) throws -> VaultRegistration {
        guard !rpId.isEmpty, !userHandle.isEmpty, userHandle.count <= 64 else { throw VaultError.invalidData }
        let keys = WebAuthn.generateKeyPair()
        let credentialID = WebAuthn.credentialID()
        guard let publicKey = Base64Std.decode(keys.publicKey) else { throw VaultError.invalidData }
        let cose = try WebAuthn.cosePublicKey(rawPublicKey: publicKey)
        var record = PasskeyRecord(id: Base64URL.encode(credentialID), credentialId: Base64URL.encode(credentialID),
                                  rpId: rpId, origin: "https://\(rpId)", userId: Base64URL.encode(userHandle),
                                  userName: userName, displayName: userName, privateKey: keys.privateKey,
                                  publicKey: keys.publicKey, createdAt: Date().timeIntervalSince1970 * 1000,
                                  counter: 0)
        record.backupEligible = true
        record.backupState = false
        record.backupSource = "created"
        let authData = WebAuthn.authenticatorData(rpId: rpId, credentialId: credentialID, cosePublicKey: cose,
                                                 includeAttestedCredentialData: true, counter: 0,
                                                 backupFlags: record.backupFlagBits)
        try archive.transaction { values in
            var entries = try records(values[Key.passkeys])
            let matches = entries.compactMap(PasskeyRecord.fromJSON).contains {
                $0.rpId == rpId && excluded.contains(Base64URL.decode($0.credentialId) ?? Data())
            }
            guard !matches else { throw VaultError.excludedCredential }
            entries.append(record.toJSON())
            values[Key.passkeys] = try encode(entries)
        }
        updateCredentialIdentities(try loadPasskeys())
        return VaultRegistration(credentialID: credentialID, attestation: WebAuthn.attestationObject(authData: authData))
    }

    private func records(_ raw: String?) throws -> [[String: Any]] {
        guard let raw else { return [] }
        guard let result = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [[String: Any]] else {
            throw VaultError.invalidData
        }
        return result
    }

    private func mergeConfig(_ local: [String: Any], _ incoming: [String: Any]) -> [String: Any] {
        var config = local.merging(incoming) { _, next in next }
        var deletions: [String: [String: Any]] = [:]
        for item in (local["deletions"] as? [[String: Any]] ?? []) +
                    (incoming["deletions"] as? [[String: Any]] ?? []) {
            guard let kind = item["kind"] as? String, let id = item["id"] as? String,
                  let time = item["deletedAt"] as? Double,
                  time.isFinite, ["passkey", "totp"].contains(kind) else { continue }
            let key = kind + ":" + id
            if time > (deletions[key]?["deletedAt"] as? Double ?? -Double.infinity) {
                deletions[key] = item
            }
        }
        config["deletions"] = deletions.keys.sorted().compactMap { deletions[$0] }
        config.removeValue(forKey: "syncSalt")
        return config
    }

    private func encode(_ value: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
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

    private func isBool(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber else { return false }
        return CFGetTypeID(number) == CFBooleanGetTypeID()
    }

    /// A copy written by a build that predates per-credential backup flags must
    /// not erase them: keep the other copy's flags when the winner has none.
    /// Mirrors carryBackupFields() in src/sync/backup-flags.ts.
    private func carryBackupFields(_ winner: [String: Any], _ other: [String: Any]) -> [String: Any] {
        guard !isBool(winner["backupEligible"]), isBool(other["backupEligible"]) else { return winner }
        var merged = winner
        merged["backupEligible"] = other["backupEligible"]
        merged["backupState"] = (other["backupState"] as? Bool) ?? false
        if let source = other["backupSource"] { merged["backupSource"] = source }
        return merged
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
                var winner = carryBackupFields(newer ? item : current, newer ? current : item)
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

    private func updateCredentialIdentities(_ records: [PasskeyRecord]) {
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
