import Foundation

// Base64 expansion must not make a supported export impossible to restore.
let payloadBytes = 25 * 1024 * 1024
let payload = Data("{\"note\":\"".utf8) + Data(repeating: 0x78, count: payloadBytes) + Data("\"}".utf8)
let encrypted = try VaultBackup.encrypt(payload, password: "size-boundary-fixture")
let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: directory) }
let file = directory.appendingPathComponent("backup.json")
try encrypted.write(to: file)
do {
    let restored = try VaultBackup.decrypt(VaultBackup.read(file), password: "size-boundary-fixture")
    precondition(restored == payload, "Large backup changed during recovery")
} catch {
    fatalError("A supported backup export could not be read and restored: \(error)")
}
print("iOS backup size boundaries: PASS")
