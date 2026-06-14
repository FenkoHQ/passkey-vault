import Foundation

/// Base64URL (no padding) helpers, matching the WebAuthn JSON wire format used by
/// the browser extension and the Android provider.
enum Base64URL {
    static func encode(_ data: Data) -> String {
        var s = data.base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        s = s.replacingOccurrences(of: "=", with: "")
        return s
    }

    static func decode(_ string: String) -> Data? {
        var s = string.replacingOccurrences(of: "-", with: "+")
        s = s.replacingOccurrences(of: "_", with: "/")
        // Re-pad to a multiple of 4.
        let remainder = s.count % 4
        if remainder > 0 {
            s.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: s)
    }
}

/// Standard base64 (with padding) — the canonical encoding for the vault's
/// `privateKey` (PKCS8 DER) and `publicKey` (raw 65-byte) fields.
enum Base64Std {
    static func encode(_ data: Data) -> String { data.base64EncodedString() }
    static func decode(_ string: String) -> Data? { Data(base64Encoded: string) }
}
