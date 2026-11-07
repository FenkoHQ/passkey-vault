import Foundation

let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
defer { try? FileManager.default.removeItem(at: directory) }
let archive = VaultArchive(directory: directory)
try archive.unlock(key: Data(repeating: 31, count: 32))
let vault = VaultStore(archive: archive)
let seed = String(repeating: "ac", count: 32)
try vault.joinSync(seedHash: seed, deviceName: "Recovery test")
let registration = try vault.register(rpId: "example.com", userName: "alice", userHandle: Data("alice".utf8), excluded: [])
let record = try vault.findPasskey(credentialId: Base64URL.encode(registration.credentialID))!
let plaintext = try VaultBackup.decrypt(vault.exportBackup(password: "fixture-password"), password: "fixture-password")
var failures: [String] = []
if String(decoding: plaintext, as: UTF8.self).contains(seed) {
    failures.append("Credential backup includes the device's sync seed")
}
let deletion = ["id": record.id, "kind": "passkey", "deletedAt": record.createdAt + 1] as [String: Any]
let config = String(decoding: try JSONSerialization.data(withJSONObject: ["deletions": [deletion]]), as: UTF8.self)
try vault.saveSnapshotFromWeb(passkeys: nil, totp: nil, syncConfig: config, syncDevices: nil, customRelays: nil)
let remaining = try vault.loadPasskeys()
precondition(remaining.isEmpty, "Test deletion did not apply")
try vault.importBackup(plaintext)
if try vault.findPasskey(credentialId: record.credentialId) == nil {
    failures.append("Explicit backup restore could not restore a deleted credential")
}
precondition(failures.isEmpty, failures.joined(separator: "; "))
print("iOS backup recovery: PASS")
