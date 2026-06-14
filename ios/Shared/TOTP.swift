import Foundation
import CryptoKit

/// RFC 6238 TOTP, matching the extension's authenticator (SHA1/256/512, variable digits).
enum TOTP {
    static func code(for entry: TOTPEntry, at date: Date = Date()) -> String? {
        guard let key = base32Decode(entry.secret) else { return nil }
        let counter = UInt64(date.timeIntervalSince1970) / UInt64(max(entry.period, 1))
        var be = counter.bigEndian
        let message = Data(bytes: &be, count: 8)
        let digest: Data
        switch entry.algorithm.uppercased() {
        case "SHA256": digest = Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        case "SHA512": digest = Data(HMAC<SHA512>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        default:       digest = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        }
        let offset = Int(digest[digest.count - 1] & 0x0f)
        let binary = (UInt32(digest[offset] & 0x7f) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        let mod = UInt32(pow(10.0, Double(entry.digits)))
        return String(format: "%0\(entry.digits)u", binary % mod)
    }

    static func secondsRemaining(for entry: TOTPEntry, at date: Date = Date()) -> Int {
        let period = max(entry.period, 1)
        return period - Int(date.timeIntervalSince1970) % period
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
