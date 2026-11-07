import CryptoKit
import Foundation

public final class SyncChunks {
    private struct Chunk: Codable {
        let version: String
        let digest: String
        let index: Int
        let total: Int
        let data: String
    }

    private struct Assembly {
        let total: Int
        let created: Date
        var parts: [Int: String] = [:]
        var requested = false
    }

    private static let chunkBytes = 12_000
    private static let maxChunks = 1400
    private static let maxAssemblies = 4
    private static let lifetime: TimeInterval = 30 * 60
    private static let requestPageSize = 50
    private var assemblies: [String: Assembly] = [:]

    public init() {}

    public static func split(_ content: String) throws -> [String] {
        // Message envelopes contain base64 and JSON syntax, so byte and JS character offsets agree.
        let bytes = Array(content.utf8)
        guard bytes.allSatisfy({ $0 < 128 }) else { throw SyncError.invalidMessage }
        guard bytes.count > chunkBytes else { return [content] }
        let total = (bytes.count + chunkBytes - 1) / chunkBytes
        guard total <= maxChunks else { throw SyncError.capacity }
        let digest = Data(SHA256.hash(data: Data(bytes))).hex
        return try (0..<total).map { index in
            let start = index * chunkBytes
            let part = String(decoding: bytes[start..<min(start + chunkBytes, bytes.count)], as: UTF8.self)
            let chunk = Chunk(version: SyncCipher.version, digest: digest, index: index, total: total, data: part)
            return String(decoding: try JSONEncoder().encode(chunk), as: UTF8.self)
        }
    }

    public func accept(_ content: String, at now: Date = Date()) throws -> String? {
        guard content.utf8.count <= SyncCipher.maxEventBytes else { throw SyncError.capacity }
        let data = Data(content.utf8)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SyncError.invalidMessage
        }
        guard object["digest"] != nil else { return content }
        let chunk = try decode(data)
        assemblies = assemblies.filter { now.timeIntervalSince($0.value.created) <= Self.lifetime }
        if assemblies[chunk.digest] == nil {
            if assemblies.count >= Self.maxAssemblies,
               let oldest = assemblies.min(by: { $0.value.created < $1.value.created })?.key {
                assemblies.removeValue(forKey: oldest)
            }
            assemblies[chunk.digest] = Assembly(total: chunk.total, created: now)
        }
        guard var assembly = assemblies[chunk.digest], assembly.total == chunk.total else {
            throw SyncError.invalidMessage
        }
        if let previous = assembly.parts[chunk.index], previous != chunk.data { throw SyncError.invalidMessage }
        assembly.parts[chunk.index] = chunk.data
        assemblies[chunk.digest] = assembly
        guard assembly.parts.count == assembly.total else { return nil }
        let joined = (0..<assembly.total).compactMap { assembly.parts[$0] }.joined()
        guard Data(SHA256.hash(data: Data(joined.utf8))).hex == chunk.digest else { throw SyncError.invalidMessage }
        // Retain completed parts so failed durable writes can retry the final event.
        return joined
    }

    public func missing(_ content: String, address: String, author: String) throws -> [String] {
        guard content.utf8.count <= SyncCipher.maxEventBytes else { throw SyncError.capacity }
        let chunk = try decode(Data(content.utf8))
        guard var assembly = assemblies[chunk.digest], !assembly.requested else { return [] }
        guard address.hasSuffix("-\(chunk.index)"), Data(hex: author)?.count == 32 else {
            throw SyncError.invalidMessage
        }
        let base = String(address.dropLast(String(chunk.index).count + 1))
        let addresses = (0..<chunk.total).map { "\(base)-\($0)" }
        let requests = try stride(from: 0, to: addresses.count, by: Self.requestPageSize).map { offset in
            let page = Array(addresses[offset..<min(offset + Self.requestPageSize, addresses.count)])
            let filter: [String: Any] = ["authors": [author], "#d": page, "limit": Self.requestPageSize,
                                         "kinds": [SyncCipher.eventKind]]
            let request: [Any] = ["REQ", "parts_\(chunk.digest)_\(offset)", filter]
            return String(decoding: try JSONSerialization.data(withJSONObject: request), as: UTF8.self)
        }
        assembly.requested = true
        assemblies[chunk.digest] = assembly
        return requests
    }

    public func reset() {
        assemblies.removeAll()
    }

    private func decode(_ data: Data) throws -> Chunk {
        let chunk = try JSONDecoder().decode(Chunk.self, from: data)
        guard chunk.version == SyncCipher.version, Data(hex: chunk.digest)?.count == 32,
              chunk.total > 0, chunk.total <= Self.maxChunks, chunk.index >= 0, chunk.index < chunk.total,
              chunk.data.utf8.count <= Self.chunkBytes, chunk.data.utf8.allSatisfy({ $0 < 128 }) else {
            throw SyncError.invalidMessage
        }
        return chunk
    }
}
