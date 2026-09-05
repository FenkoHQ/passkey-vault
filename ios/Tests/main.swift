import Foundation

let suite = "nz.fenko.sync-tests.\(UUID().uuidString)"
let defaults = UserDefaults(suiteName: suite)!
defer { defaults.removePersistentDomain(forName: suite) }
let vault = VaultStore(suiteName: suite)
let record: [String: Any] = [
    "id": "p", "credentialId": "cA", "rpId": "example.com",
    "privateKey": "keep", "publicKey": "keep-public", "createdAt": 1.0,
    "counter": 9, "prfKey": "keep-prf", "updatedAt": 1.0,
]
func json(_ value: Any) -> String {
    String(data: try! JSONSerialization.data(withJSONObject: value), encoding: .utf8)!
}
func require(_ condition: Bool, _ message: String) {
    if !condition { fatalError(message) }
}
defaults.set(json([record]), forKey: "passkeys")
vault.saveSnapshotFromWeb(passkeys: "[]", totp: "[]", syncConfig: "{}", syncDevices: nil, customRelays: nil)
require(vault.loadPasskeys().count == 1, "stale WebView removed native credential")
var stale = record
stale["counter"] = 1
vault.saveSnapshotFromWeb(passkeys: json([stale]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
require(vault.loadPasskeys().first?.counter == 9, "counter rolled back")
let deletion: [String: Any] = ["kind": "passkey", "id": "p", "deletedAt": 2.0]
vault.saveSnapshotFromWeb(passkeys: "[]", totp: nil, syncConfig: json(["deletions": [deletion]]), syncDevices: nil, customRelays: nil)
require(vault.loadPasskeys().isEmpty, "deletion ignored")
vault.saveSnapshotFromWeb(passkeys: json([stale]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
require(vault.loadPasskeys().isEmpty, "stale snapshot resurrected deletion")
var restored = record
restored["updatedAt"] = 3.0
vault.saveSnapshotFromWeb(passkeys: json([restored]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
require(vault.loadPasskeys().count == 1, "restore ignored")
var signed = vault.loadPasskeys()[0]
signed.counter += 1
vault.upsert(signed)
let result = vault.loadPasskeys()[0].toJSON()
require(result["prfKey"] as? String == "keep-prf", "native sign discarded PRF key")
require(result["updatedAt"] as? Double == 3.0, "native sign discarded restore revision")
var a = restored
a["updatedAt"] = 4.5
a["label"] = "a"
var z = a
z["label"] = "z"
for pair in [[a, z], [z, a]] {
    defaults.set(json([pair[0]]), forKey: "passkeys")
    vault.saveSnapshotFromWeb(passkeys: json([pair[1]]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
    require(vault.loadPasskeys()[0].toJSON()["label"] as? String == "z", "equal revision depends on arrival order")
}
vault.saveSnapshotFromWeb(passkeys: "[]", totp: nil, syncConfig: "{\"resetVault\":true}", syncDevices: nil, customRelays: nil)
require(vault.loadPasskeys().count == 1, "config must not reset the vault")
vault.resetVault()
require(vault.loadPasskeys().isEmpty, "explicit reset failed")
print("iOS native snapshot merge: PASS")
