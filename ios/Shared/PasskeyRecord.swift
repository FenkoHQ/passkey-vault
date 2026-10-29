import Foundation

/// One stored passkey. Mirrors the JSON shape used by the browser extension and
/// `ProviderVaultStore.PasskeyRecord` on Android, so a vault synced from any
/// platform round-trips losslessly. Unknown keys are preserved in `extra` so we
/// never drop fields another platform wrote.
struct PasskeyRecord: Codable {
    var id: String
    var credentialId: String
    var rpId: String
    var origin: String
    var userId: String?
    var userName: String
    var displayName: String
    /// PKCS8 DER, standard base64 (the cross-platform canonical encoding).
    var privateKey: String
    /// Raw uncompressed P-256 point (0x04 || X || Y), standard base64.
    var publicKey: String
    var createdAt: Double
    var counter: Int
    /// Per-credential WebAuthn backup flags (see src/sync/backup-flags.ts).
    /// Nil on a record from before they existed: sign as this app always has.
    var backupEligible: Bool? = nil
    var backupState: Bool? = nil
    var backupSource: String? = nil
    private var original: Data? = nil

    init(id: String, credentialId: String, rpId: String, origin: String,
         userId: String?, userName: String, displayName: String,
         privateKey: String, publicKey: String, createdAt: Double, counter: Int) {
        self.id = id
        self.credentialId = credentialId
        self.rpId = rpId
        self.origin = origin
        self.userId = userId
        self.userName = userName
        self.displayName = displayName
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.createdAt = createdAt
        self.counter = counter
    }

    /// BE (0x08) and BS (0x10) for this credential. Relying parties such as
    /// Teleport store BE and reject a sign-in that changes it.
    var backupFlagBits: UInt8 {
        guard backupEligible == true else { return 0 }
        return backupState == true ? 0x18 : 0x08
    }

    // MARK: JSON (hand-rolled to tolerate the nested `user` object and loose types)

    static func fromJSON(_ obj: [String: Any]) -> PasskeyRecord? {
        let credentialId = (obj["credentialId"] as? String) ?? (obj["id"] as? String) ?? ""
        let privateKey = obj["privateKey"] as? String ?? ""
        let rpId = obj["rpId"] as? String ?? ""
        guard !credentialId.isEmpty, !privateKey.isEmpty, !rpId.isEmpty else { return nil }

        let user = obj["user"] as? [String: Any]
        var record = PasskeyRecord(
            id: (obj["id"] as? String) ?? credentialId,
            credentialId: StoredCredentialID.credentialId(credentialId),
            rpId: rpId,
            origin: (obj["origin"] as? String) ?? "https://\(rpId)",
            userId: user?["id"] as? String,
            userName: (user?["name"] as? String) ?? "",
            displayName: (user?["displayName"] as? String) ?? "",
            privateKey: privateKey,
            publicKey: (obj["publicKey"] as? String) ?? "",
            createdAt: (obj["createdAt"] as? Double) ?? Date().timeIntervalSince1970 * 1000,
            counter: (obj["counter"] as? Int) ?? 0
        )
        // JSONSerialization hands booleans back as NSNumber; only a real
        // boolean counts, so a stray 0/1 cannot pose as a flag.
        if let be = obj["backupEligible"] as? NSNumber, CFGetTypeID(be) == CFBooleanGetTypeID() {
            record.backupEligible = be.boolValue
            record.backupState = be.boolValue && ((obj["backupState"] as? Bool) ?? false)
            record.backupSource = obj["backupSource"] as? String
        }
        record.original = try? JSONSerialization.data(withJSONObject: obj)
        return record
    }

    func toJSON() -> [String: Any] {
        var user: [String: Any] = ["name": userName, "displayName": displayName]
        user["id"] = userId as Any? ?? NSNull()
        var result = original.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
        let fields: [String: Any] = [
            "id": id,
            "credentialId": credentialId,
            "type": "public-key",
            "rpId": rpId,
            "origin": origin.isEmpty ? "https://\(rpId)" : origin,
            "user": user,
            "privateKey": privateKey,
            "publicKey": publicKey,
            "createdAt": createdAt,
            "counter": counter,
        ]
        result.merge(fields) { _, next in next }
        if let backupEligible {
            result["backupEligible"] = backupEligible
            result["backupState"] = backupEligible && (backupState ?? false)
            if let backupSource { result["backupSource"] = backupSource }
        }
        return result
    }
}

/// One TOTP/2FA entry. Display + code generation only; secrets stay in the App Group.
struct TOTPEntry: Codable, Identifiable {
    var id: String
    var issuer: String
    var account: String
    /// Base32 secret.
    var secret: String
    var algorithm: String   // SHA1 | SHA256 | SHA512
    var digits: Int
    var period: Int

    static func fromJSON(_ obj: [String: Any]) -> TOTPEntry? {
        guard let secret = obj["secret"] as? String, !secret.isEmpty else { return nil }
        return TOTPEntry(
            id: (obj["id"] as? String) ?? UUID().uuidString,
            issuer: (obj["issuer"] as? String) ?? "",
            account: (obj["account"] as? String) ?? (obj["label"] as? String) ?? "",
            secret: secret,
            algorithm: (obj["algorithm"] as? String) ?? "SHA1",
            digits: (obj["digits"] as? Int) ?? 6,
            period: (obj["period"] as? Int) ?? 30
        )
    }
}
