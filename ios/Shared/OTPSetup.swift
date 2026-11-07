import Foundation

enum OTPAlgorithm: String, CaseIterable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"
}

struct OTPSetup {
    let kind: OTPKind
    let issuer: String
    let account: String
    let secret: String
    let algorithm: OTPAlgorithm
    let digits: Int
    let period: Int
    let counter: UInt64
    private static let maxLabelBytes = 256
    private static let maxURIBytes = 16 * 1024

    static func fromURI(_ uri: String) throws -> OTPSetup {
        guard uri.utf8.count <= maxURIBytes,
              let url = URLComponents(string: uri.trimmingCharacters(in: .whitespacesAndNewlines)),
              url.scheme?.lowercased() == "otpauth", let host = url.host?.lowercased(),
              let kind = OTPKind(rawValue: host), url.user == nil, url.password == nil,
              url.port == nil, url.fragment == nil else { throw VaultError.invalidData }
        let items = url.queryItems ?? []
        guard Set(items.map(\.name)).count == items.count else { throw VaultError.invalidData }
        let query = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
        guard let secret = query["secret"], !secret.isEmpty,
              let algorithm = OTPAlgorithm(rawValue: (query["algorithm"] ?? "SHA1").uppercased()),
              let digits = Int(query["digits"] ?? "6"), let period = Int(query["period"] ?? "30"),
              let counter = UInt64(query["counter"] ?? "0") else { throw VaultError.invalidData }
        let label = String(url.path.drop(while: { $0 == "/" }))
        let parts = label.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        let issuer = query["issuer"] ?? (parts.count == 2 ? String(parts[0]) : "")
        let account = parts.count == 2 ? String(parts[1]) : label
        let setup = OTPSetup(kind: kind, issuer: issuer, account: account, secret: secret,
                             algorithm: algorithm, digits: digits, period: period, counter: counter)
        _ = try setup.record()
        return setup
    }

    func record(at date: Date = Date()) throws -> [String: Any] {
        let issuer = issuer.trimmingCharacters(in: .whitespacesAndNewlines)
        let account = account.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !issuer.isEmpty || !account.isEmpty,
              issuer.utf8.count <= Self.maxLabelBytes, account.utf8.count <= Self.maxLabelBytes else {
            throw VaultError.invalidData
        }
        let entry = TOTPEntry(id: UUID().uuidString, issuer: issuer, account: account, secret: secret,
                              algorithm: algorithm.rawValue, digits: digits, period: period, kind: kind, counter: counter)
        guard TOTP.isValid(entry), let secretB64 = TOTP.canonicalSecret(entry) else { throw VaultError.invalidData }
        let now = date.timeIntervalSince1970 * 1000
        return ["id": entry.id, "type": kind.rawValue, "issuer": issuer, "account": account,
                "secretB64": secretB64, "algorithm": algorithm.rawValue, "digits": digits,
                "period": period, "counter": counter, "createdAt": now, "updatedAt": now]
    }
}
