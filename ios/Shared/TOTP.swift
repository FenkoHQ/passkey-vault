import Foundation
import CryptoKit

/// RFC 6238 TOTP, matching the extension's authenticator (SHA1/256/512, variable digits).
enum TOTP {
    static let maxCounter: UInt64 = 9_007_199_254_740_991
    private static let minDigits = 6
    private static let maxDigits = 10
    private static let maxSecretBytes = 4096

    static func isValid(_ entry: TOTPEntry) -> Bool {
        (minDigits...maxDigits).contains(entry.digits) && entry.period > 0 && entry.counter <= maxCounter &&
            ["SHA1", "SHA256", "SHA512"].contains(entry.algorithm.uppercased()) && key(for: entry) != nil
    }

    static func canonicalSecret(_ entry: TOTPEntry) -> String? {
        key(for: entry)?.base64EncodedString()
    }

    static func code(for entry: TOTPEntry, at date: Date = Date()) -> String? {
        guard isValid(entry), let key = key(for: entry) else { return nil }
        let counter: UInt64
        if entry.kind == .hotp {
            counter = entry.counter
        } else {
            let interval = date.timeIntervalSince1970
            let step = floor(interval / Double(entry.period))
            guard interval.isFinite, interval >= 0, step <= Double(maxCounter) else { return nil }
            counter = UInt64(step)
        }
        var be = counter.bigEndian
        let message = Data(bytes: &be, count: 8)
        let digest: Data
        switch entry.algorithm.uppercased() {
        case "SHA256": digest = Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        case "SHA512": digest = Data(HMAC<SHA512>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        case "SHA1": digest = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        default: return nil
        }
        let offset = Int(digest[digest.count - 1] & 0x0f)
        let binary = (UInt32(digest[offset] & 0x7f) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        let modulus = (0..<entry.digits).reduce(UInt64(1)) { value, _ in value * 10 }
        let code = String(UInt64(binary) % modulus)
        return String(repeating: "0", count: entry.digits - code.count) + code
    }

    static func secondsRemaining(for entry: TOTPEntry, at date: Date = Date()) -> Int {
        let interval = date.timeIntervalSince1970
        guard entry.kind == .totp, entry.period > 0, interval.isFinite, interval >= 0,
              interval <= Double(maxCounter) else { return 0 }
        return entry.period - Int(interval) % entry.period
    }

    private static func key(for entry: TOTPEntry) -> Data? {
        let decoded: Data?
        if let base64 = entry.secretB64 {
            guard base64.utf8.count <= maxSecretBytes * 2 else { return nil }
            decoded = Data(base64Encoded: base64)
        } else {
            guard entry.secret.utf8.count <= maxSecretBytes * 2 else { return nil }
            decoded = base32Decode(entry.secret)
        }
        guard let decoded, !decoded.isEmpty, decoded.count <= maxSecretBytes else { return nil }
        return decoded
    }

    private static func base32Decode(_ string: String) -> Data? {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        let clean = string.uppercased().replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: " ", with: "")
        var bits = 0, value = 0
        var out = Data()
        for ch in clean {
            guard let idx = alphabet.firstIndex(of: ch) else { return nil }
            value = (value << 5) | alphabet.distance(from: alphabet.startIndex, to: idx)
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((value >> bits) & 0xff))
            }
        }
        return out.isEmpty ? nil : out
    }
}
