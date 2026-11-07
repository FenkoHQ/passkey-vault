import Foundation

func require(_ value: Bool, _ message: String) {
    precondition(value, message)
}

func expectFailure(_ message: String, _ operation: () throws -> Void) {
    do {
        try operation()
    } catch { return }
    fatalError(message)
}

let suite = "nz.fenko.storage-regression.\(UUID().uuidString)"
let defaults = UserDefaults(suiteName: suite)!
let directory = FileManager.default.temporaryDirectory.appendingPathComponent(suite)
defer {
    defaults.removePersistentDomain(forName: suite)
    try? FileManager.default.removeItem(at: directory)
}
let key = Data(repeating: 42, count: 32)
let archive = VaultArchive(directory: directory)
let vault = VaultStore(archive: archive, legacy: defaults)
let record: [String: Any] = [
    "id": "credential", "credentialId": "Y3JlZGVudGlhbA", "rpId": "example.com",
    "privateKey": "storage-regression-private-key", "publicKey": "public-key",
    "createdAt": 1.0, "counter": 0,
]
let raw = String(decoding: try JSONSerialization.data(withJSONObject: [record]), as: UTF8.self)
defaults.set(raw, forKey: "passkeys")

expectFailure("Locked migration must fail") { try vault.migrateLegacy() }
require(defaults.string(forKey: "passkeys") == raw, "Failed migration deleted the source")
try archive.unlock(key: key)
try vault.migrateLegacy()
require(try vault.loadPasskeys().count == 1, "Migration lost the credential")
require(defaults.string(forKey: "passkeys") == nil, "Migration left plaintext preferences")
try vault.savePasskeys([PasskeyRecord.fromJSON(record)!])
require(!defaults.dictionaryRepresentation().description.contains("storage-regression-private-key"),
        "Private keys remain readable in shared UserDefaults")

let file = directory.appendingPathComponent("vault.encrypted")
let ciphertext = try Data(contentsOf: file)
require(!String(decoding: ciphertext, as: UTF8.self).contains("storage-regression-private-key"),
        "Private keys remain readable on disk")
expectFailure("Transaction must propagate failure") {
    try archive.transaction { values in
        values["passkeys"] = "[]"
        throw VaultError.invalidData
    }
}
require(try Data(contentsOf: file) == ciphertext, "Failed transaction changed the archive")

// Independent readers must merge into the latest committed state, not a cached snapshot.
let peer = VaultArchive(directory: directory)
try peer.unlock(key: key)
try peer.transaction { $0["peer"] = "first" }
try archive.transaction { $0["local"] = "second" }
require(try peer.read()["local"] == "second", "Cross-instance write was lost")
require(try archive.read()["peer"] == "first", "Stale writer overwrote peer data")
vault.lock()
expectFailure("Locked reads must fail") { _ = try vault.loadPasskeys() }
expectFailure("Locked writes must fail") { try vault.resetVault() }
expectFailure("Wrong key must fail") { try archive.unlock(key: Data(repeating: 43, count: 32)) }
expectFailure("Wrong key unlocked the archive") { _ = try archive.read() }
try archive.unlock(key: key)
require(try vault.loadPasskeys().count == 1, "Reopening lost the credential")

let intact = try Data(contentsOf: file)
try Data("damaged archive".utf8).write(to: file)
expectFailure("Corruption must not look like an empty vault") { _ = try vault.loadPasskeys() }
expectFailure("Corruption must not be overwritten") { try vault.resetVault() }
require(try Data(contentsOf: file) == Data("damaged archive".utf8), "Corrupt file was overwritten")
try intact.write(to: file)
require(try vault.loadPasskeys().count == 1, "Restored ciphertext could not be read")

// A malformed legacy value must survive for recovery, without a partial encrypted commit.
let badArchive = VaultArchive(directory: directory.appendingPathComponent("invalid"))
try badArchive.unlock(key: key)
defaults.set("invalid-json", forKey: "passkeys")
let badVault = VaultStore(archive: badArchive, legacy: defaults)
expectFailure("Malformed legacy data must fail") { try badVault.migrateLegacy() }
require(defaults.string(forKey: "passkeys") == "invalid-json", "Malformed source was deleted")
require(!badArchive.exists, "Failed migration committed an archive")
print("iOS encrypted storage: PASS")
