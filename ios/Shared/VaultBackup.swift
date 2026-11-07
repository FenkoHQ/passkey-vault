import CommonCrypto
import CryptoKit
import Foundation

enum VaultBackup {
    private static let rounds: UInt32 = 100_000
    private static let keyBytes = 32
    private static let saltBytes = 32
    private static let nonceBytes = 12
    private static let tagBytes = 16
    private static let maxBytes = 32 * 1024 * 1024

    private struct Envelope: Codable {
        let encrypted: Bool
        let version: String
        let algorithm: String
        let data: String
        let iv: String
        let salt: String
    }

    static func encrypt(_ plaintext: Data, password: String) throws -> Data {
        guard !password.isEmpty, plaintext.count <= maxBytes else { throw VaultError.invalidData }
        let salt = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let key = try derive(password, salt: salt)
        let box = try AES.GCM.seal(plaintext, using: key)
        let envelope = Envelope(encrypted: true, version: "1.0", algorithm: "AES-256-GCM",
                                data: (box.ciphertext + box.tag).base64EncodedString(),
                                iv: box.nonce.withUnsafeBytes { Data($0) }.base64EncodedString(),
                                salt: salt.base64EncodedString())
        return try JSONEncoder().encode(envelope)
    }

    static func decrypt(_ data: Data, password: String) throws -> Data {
        guard data.count <= maxBytes else { throw VaultError.invalidData }
        let object = try JSONSerialization.jsonObject(with: data)
        guard let root = object as? [String: Any], root["encrypted"] as? Bool == true else {
            return data
        }
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        guard envelope.version == "1.0", envelope.algorithm == "AES-256-GCM",
              let salt = Data(base64Encoded: envelope.salt), salt.count == saltBytes,
              let nonce = Data(base64Encoded: envelope.iv), nonce.count == nonceBytes,
              let ciphertext = Data(base64Encoded: envelope.data), ciphertext.count >= tagBytes,
              !password.isEmpty else { throw VaultError.invalidData }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
                                       ciphertext: ciphertext.dropLast(tagBytes),
                                       tag: ciphertext.suffix(tagBytes))
        return try AES.GCM.open(box, using: derive(password, salt: salt))
    }

    static func read(_ url: URL) throws -> Data {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size <= maxBytes else { throw VaultError.invalidData }
        return try Data(contentsOf: url)
    }

    private static func derive(_ password: String, salt: Data) throws -> SymmetricKey {
        let passwordBytes = Array(password.utf8)
        var result = Data(count: keyBytes)
        let status = result.withUnsafeMutableBytes { output in
            salt.withUnsafeBytes { saltBuffer in
                passwordBytes.withUnsafeBytes { passwordBuffer in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                        passwordBuffer.baseAddress?.assumingMemoryBound(to: CChar.self),
                                        passwordBytes.count,
                                        saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                        salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds,
                                        output.baseAddress?.assumingMemoryBound(to: UInt8.self), keyBytes)
                }
            }
        }
        guard status == kCCSuccess else { throw VaultError.invalidData }
        return SymmetricKey(data: result)
    }
}
