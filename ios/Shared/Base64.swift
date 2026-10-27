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

/// The credential ID a relying party knows for a stored ID. Bitwarden exports
/// write 16-byte IDs as GUIDs and other lengths as "b64." + base64url; the web
/// app re-keys such records when it next runs, so until then read them here.
/// Mirrors `decodeBitwardenCredentialId` in src/sync/credential-ids.ts.
enum StoredCredentialID {
    private static let bitwardenB64Prefix = "b64."
    private static let guid = try! NSRegularExpression(
        pattern: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    static func credentialId(_ stored: String) -> String {
        let value = stored.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix(bitwardenB64Prefix) {
            var encoded = String(value.dropFirst(bitwardenB64Prefix.count))
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
            while encoded.hasSuffix("=") { encoded.removeLast() }
            return encoded.isEmpty ? stored : encoded
        }
        let range = NSRange(value.startIndex..., in: value)
        guard guid.firstMatch(in: value, range: range) != nil else { return stored }
        let hex = Array(value.replacingOccurrences(of: "-", with: ""))
        var bytes = Data()
        for i in stride(from: 0, to: hex.count, by: 2) {
            guard let byte = UInt8(String(hex[i..<i + 2]), radix: 16) else { return stored }
            bytes.append(byte)
        }
        return Base64URL.encode(bytes)
    }
}
