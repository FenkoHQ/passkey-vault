import Foundation

func require(_ condition: Bool, _ message: String) { precondition(condition, message) }
func expectFailure(_ operation: () throws -> Void) {
    do { try operation() } catch { return }
    fatalError("Expected storage operation to fail")
}

let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
defer { try? FileManager.default.removeItem(at: directory) }
let archive = VaultArchive(directory: directory)
try archive.unlock(key: Data(repeating: 9, count: 32))
let vault = VaultStore(archive: archive)
let seed = String(repeating: "ab", count: 32)
try vault.joinSync(seedHash: seed, deviceName: "iPhone")
let settings = try vault.syncSettings()!
require(settings.seedHash == seed && settings.chainID == String(seed.prefix(32)), "Sync identity was not stored")
let registration = try vault.register(rpId: "example.com", userName: "alice", userHandle: Data("alice".utf8), excluded: [])
let record = try vault.findPasskey(credentialId: Base64URL.encode(registration.credentialID))!
try vault.savePasskeys([])
let peer = VaultPeer(id: "browser", name: "Browser", type: "Desktop", lastSeen: 1000)
var payload: [String: Any] = ["passkeys": [record.toJSON()], "totpEntries": [], "deletions": [],
                              "syncConfig": ["seedHash": "untrusted-key"]]
let data = try JSONSerialization.data(withJSONObject: payload)
require(try vault.applySync(data, peer: peer), "First snapshot was not marked changed")
require(try !vault.applySync(data, peer: peer), "Identical snapshot caused a sync echo")
require(try vault.loadPasskeys().count == 1, "Remote credential was lost")
require(try vault.syncSettings()!.seedHash == seed, "Remote data replaced local sync identity")
require(try vault.syncPeers().contains { $0.id == "browser" }, "Peer metadata was not stored")
let outbound = String(decoding: try vault.syncSnapshot(), as: UTF8.self)
require(!outbound.contains(seed) && !outbound.contains(settings.deviceID), "Outbound snapshot exposed local identity")

let before = try archive.read()
payload["passkeys"] = [["id": "invalid", "rpId": "example.com", "privateKey": ""]]
expectFailure { _ = try vault.applySync(JSONSerialization.data(withJSONObject: payload), peer: peer) }
require(try archive.read() == before, "Invalid snapshot partially changed the vault")
payload["passkeys"] = []
payload["deletions"] = [["kind": "passkey", "id": record.id, "deletedAt": record.createdAt + 1]]
require(try vault.applySync(JSONSerialization.data(withJSONObject: payload), peer: peer), "Deletion did not change the vault")
require(try vault.loadPasskeys().isEmpty, "Deleted credential survived")
require(try !vault.applySync(data, peer: peer), "Stale snapshot restored a deleted credential")
try vault.leaveSync()
require(try vault.syncSettings() == nil, "Leaving sync kept the chain active")
require(try !vault.snapshotJSON().contains(seed), "Leaving sync retained the seed hash")
expectFailure { _ = try vault.applySync(data, peer: peer) }
vault.lock()
expectFailure { _ = try vault.syncSnapshot() }
print("iOS sync storage transactions: PASS")
