import CommonCrypto
import CryptoKit
import Foundation
import P256K

public struct SyncBox: Codable, Sendable {
    public let nonce: String
    public let ciphertext: String

    public init(nonce: String, ciphertext: String) {
        self.nonce = nonce
        self.ciphertext = ciphertext
    }
}

public struct RelayEvent: Codable, Sendable {
    public let id: String
    public let pubkey: String
    public let createdAt: Int64
    public let kind: Int
    public let tags: [[String]]
    public let content: String
    public let sig: String

    enum CodingKeys: String, CodingKey {
        case id, pubkey, kind, tags, content, sig
        case createdAt = "created_at"
    }
}

// Key material stays inside this driver. Callers exchange encrypted messages and signed events.
public final class SyncCipher {
    public static let eventKind = 30078
    public static let version = "4.0"
    public static let maxEventBytes = 16_384
    public let chainID: String
    public let author: String
    private let encryptionKey: SymmetricKey
    private let signingKey: P256K.Schnorr.PrivateKey
    private static let rounds: UInt32 = 100_000
    private static let keyBytes = 32
    private static let nonceBytes = 12
    private static let tagBytes = 16
    private static let maxMessageBytes = 32 * 1024 * 1024
    private static let signatureBytes = 64
    private static let maxExactTimestamp: Int64 = 9_007_199_254_740_991
    private static let maxTags = 64
    private static let maxTagFields = 8
    private static let maxTagBytes = 2048

    private struct MessageBox: Codable {
        let n: String
        let c: String
    }

    public init(seedHash: String) throws {
        guard Data(hex: seedHash)?.count == Self.keyBytes else { throw SyncError.invalidKey }
        chainID = String(seedHash.prefix(32))
        let prefix = "pkvault-sync-v4-\(chainID)"
        encryptionKey = SymmetricKey(data: try Self.derive(seedHash, salt: "\(prefix)-enc"))
        signingKey = try P256K.Schnorr.PrivateKey(dataRepresentation: Self.derive(seedHash, salt: "\(prefix)-nostr"))
        author = Data(signingKey.xonly.bytes).hex
    }

    public func seal(_ plaintext: Data) throws -> SyncBox {
        guard plaintext.count <= Self.maxMessageBytes else { throw SyncError.capacity }
        let box = try AES.GCM.seal(plaintext, using: encryptionKey)
        return SyncBox(nonce: box.nonce.withUnsafeBytes { Data($0) }.base64EncodedString(),
                       ciphertext: (box.ciphertext + box.tag).base64EncodedString())
    }

    public func open(_ box: SyncBox) throws -> Data {
        guard box.ciphertext.utf8.count <= Self.maxMessageBytes * 2,
              let nonce = Data(base64Encoded: box.nonce), nonce.count == Self.nonceBytes,
              let ciphertext = Data(base64Encoded: box.ciphertext),
              ciphertext.count >= Self.tagBytes, ciphertext.count <= Self.maxMessageBytes + Self.tagBytes else {
            throw SyncError.invalidMessage
        }
        return try AES.GCM.open(AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
                                                 ciphertext: ciphertext.dropLast(Self.tagBytes),
                                                 tag: ciphertext.suffix(Self.tagBytes)), using: encryptionKey)
    }

    public func encryptMessage(_ plaintext: Data) throws -> String {
        let box = try seal(plaintext)
        return String(decoding: try JSONEncoder().encode(MessageBox(n: box.nonce, c: box.ciphertext)), as: UTF8.self)
    }

    public func decryptMessage(_ content: String) throws -> Data {
        guard content.utf8.count <= Self.maxMessageBytes * 2 else { throw SyncError.capacity }
        let box = try JSONDecoder().decode(MessageBox.self, from: Data(content.utf8))
        return try open(SyncBox(nonce: box.n, ciphertext: box.c))
    }

    public func sign(content: String, tags: [[String]], createdAt: Int64) throws -> RelayEvent {
        let digest = try eventHash(author: author, createdAt: createdAt, kind: Self.eventKind,
                                   tags: tags, content: content)
        var message = Array(digest)
        var auxiliary = SymmetricKey(size: .bits256).withUnsafeBytes { Array($0) }
        let signature = try signingKey.signature(message: &message, auxiliaryRand: &auxiliary, strict: true)
        let event = RelayEvent(id: digest.hex, pubkey: author, createdAt: createdAt, kind: Self.eventKind,
                               tags: tags, content: content, sig: signature.dataRepresentation.hex)
        guard try JSONEncoder().encode(event).count <= Self.maxEventBytes else { throw SyncError.capacity }
        return event
    }

    public func verify(_ event: RelayEvent) -> Bool {
        guard event.pubkey == author, event.kind == Self.eventKind,
              let signature = Data(hex: event.sig), signature.count == Self.signatureBytes,
              let digest = try? eventHash(author: event.pubkey, createdAt: event.createdAt, kind: event.kind,
                                          tags: event.tags, content: event.content),
              digest.hex == event.id,
              let parsed = try? P256K.Schnorr.SchnorrSignature(dataRepresentation: signature),
              let encoded = try? JSONEncoder().encode(event), encoded.count <= Self.maxEventBytes else {
            return false
        }
        var bytes = Array(digest)
        return signingKey.xonly.isValid(parsed, for: &bytes)
    }

    private func eventHash(author: String, createdAt: Int64, kind: Int,
                            tags: [[String]], content: String) throws -> Data {
        guard createdAt >= 0, createdAt <= Self.maxExactTimestamp,
              content.utf8.count <= Self.maxEventBytes,
              tags.count <= Self.maxTags,
              tags.allSatisfy({ $0.count <= Self.maxTagFields && $0.allSatisfy { $0.utf8.count <= Self.maxTagBytes } }) else {
            throw SyncError.invalidEvent
        }
        let canonical: [Any] = [0, author, createdAt, kind, tags, content]
        let data = try JSONSerialization.data(withJSONObject: canonical, options: [.withoutEscapingSlashes])
        return Data(SHA256.hash(data: data))
    }

    private static func derive(_ password: String, salt: String) throws -> Data {
        let input = Array(password.utf8)
        let saltBytes = Array(salt.utf8)
        var output = Data(count: keyBytes)
        let result = output.withUnsafeMutableBytes { result in
            input.withUnsafeBytes { password in
                saltBytes.withUnsafeBytes { salt in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                        password.baseAddress?.assumingMemoryBound(to: CChar.self), input.count,
                                        salt.baseAddress?.assumingMemoryBound(to: UInt8.self), saltBytes.count,
                                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds,
                                        result.baseAddress?.assumingMemoryBound(to: UInt8.self), keyBytes)
                }
            }
        }
        guard result == kCCSuccess else { throw SyncError.invalidKey }
        return output
    }
}
