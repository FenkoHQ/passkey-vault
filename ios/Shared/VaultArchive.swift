import CryptoKit
import Darwin
import Foundation
import Security

enum VaultError: LocalizedError {
    case locked
    case unavailable
    case invalidArchive
    case missingKey
    case invalidData
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .locked: return "Unlock Fenko Vault to continue."
        case .unavailable: return "Shared vault storage is unavailable. Check the app installation."
        case .invalidArchive: return "The vault could not be opened. Your stored data has not been replaced."
        case .missingKey: return "The vault key is unavailable. Restore an encrypted backup."
        case .invalidData: return "The vault data is invalid."
        case .keychain: return "The device could not unlock the vault key."
        }
    }
}

// The file contains ciphertext only. The stable lock file coordinates app and provider writes.
final class VaultArchive {
    private struct Envelope: Codable {
        let version: Int
        let sealed: Data
    }

    private static let version = 1
    private static let filename = "vault.encrypted"
    private static let lockName = "vault.lock"
    private static let keyBytes = 32
    private static let maxBytes = 32 * 1024 * 1024
    private static let authenticatedData = Data("Fenko Vault iOS archive v1".utf8)
    private let directory: URL?
    private let mutex = NSRecursiveLock()
    private var key: SymmetricKey?

    init(directory: URL?) {
        self.directory = directory
    }

    var exists: Bool {
        guard let directory else { return false }
        return FileManager.default.fileExists(atPath: directory.appendingPathComponent(Self.filename).path)
    }

    func unlock(key bytes: Data) throws {
        mutex.lock()
        defer { mutex.unlock() }
        guard bytes.count == Self.keyBytes else { throw VaultError.missingKey }
        let candidate = SymmetricKey(data: bytes)
        try coordinated { url in
            _ = try read(url, using: candidate)
        }
        key = candidate
    }

    func lock() {
        mutex.lock()
        defer { mutex.unlock() }
        key = nil
    }

    func read() throws -> [String: String] {
        mutex.lock()
        defer { mutex.unlock() }
        guard let key else { throw VaultError.locked }
        return try coordinated { try read($0, using: key) }
    }

    @discardableResult
    func transaction<T>(_ change: (inout [String: String]) throws -> T) throws -> T {
        mutex.lock()
        defer { mutex.unlock() }
        guard let key else { throw VaultError.locked }
        return try coordinated { url in
            var values = try read(url, using: key)
            let result = try change(&values)
            let plaintext = try JSONEncoder().encode(values)
            guard plaintext.count <= Self.maxBytes else { throw VaultError.invalidData }
            let box = try AES.GCM.seal(plaintext, using: key, authenticating: Self.authenticatedData)
            guard let sealed = box.combined else { throw VaultError.invalidArchive }
            let data = try JSONEncoder().encode(Envelope(version: Self.version, sealed: sealed))
            var options: Data.WritingOptions = [.atomic]
            #if os(iOS)
            options.insert(.completeFileProtection)
            #endif
            try data.write(to: url, options: options)
            let file = try FileHandle(forWritingTo: url)
            defer { try? file.close() }
            try file.synchronize()
            return result
        }
    }

    private func read(_ url: URL, using key: SymmetricKey) throws -> [String: String] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [:] }
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size <= Self.maxBytes * 2 else { throw VaultError.invalidArchive }
        do {
            let envelope = try JSONDecoder().decode(Envelope.self, from: Data(contentsOf: url))
            guard envelope.version == Self.version else { throw VaultError.invalidArchive }
            let box = try AES.GCM.SealedBox(combined: envelope.sealed)
            let data = try AES.GCM.open(box, using: key, authenticating: Self.authenticatedData)
            return try JSONDecoder().decode([String: String].self, from: data)
        } catch {
            throw VaultError.invalidArchive
        }
    }

    private func coordinated<T>(_ operation: (URL) throws -> T) throws -> T {
        guard var directory else { throw VaultError.unavailable }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        var resources = URLResourceValues()
        resources.isExcludedFromBackup = true
        try directory.setResourceValues(resources)
        let path = directory.appendingPathComponent(Self.lockName).path
        let descriptor = Darwin.open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw POSIXError(.EIO) }
        defer { Darwin.close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw POSIXError(.EIO) }
        defer { flock(descriptor, LOCK_UN) }
        return try operation(directory.appendingPathComponent(Self.filename))
    }
}
