import Foundation

let suite = "nz.fenko.sync-tests.\(UUID().uuidString)"
let defaults = UserDefaults(suiteName: suite)!
defer { defaults.removePersistentDomain(forName: suite) }
let directory = FileManager.default.temporaryDirectory.appendingPathComponent(suite)
defer { try? FileManager.default.removeItem(at: directory) }
let archive = VaultArchive(directory: directory)
try archive.unlock(key: Data(repeating: 7, count: 32))
let vault = VaultStore(archive: archive)
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
try archive.transaction { $0["passkeys"] = json([record]) }
try vault.saveSnapshotFromWeb(passkeys: "[]", totp: "[]", syncConfig: "{}", syncDevices: nil, customRelays: nil)
require(try vault.loadPasskeys().count == 1, "stale WebView removed native credential")
var stale = record
stale["counter"] = 1
try vault.saveSnapshotFromWeb(passkeys: json([stale]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
require(try vault.loadPasskeys().first?.counter == 9, "counter rolled back")
let deletion: [String: Any] = ["kind": "passkey", "id": "p", "deletedAt": 2.0]
try vault.saveSnapshotFromWeb(passkeys: "[]", totp: nil, syncConfig: json(["deletions": [deletion]]), syncDevices: nil, customRelays: nil)
require(try vault.loadPasskeys().isEmpty, "deletion ignored")
try vault.saveSnapshotFromWeb(passkeys: json([stale]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
require(try vault.loadPasskeys().isEmpty, "stale snapshot resurrected deletion")
var restored = record
restored["updatedAt"] = 3.0
try vault.saveSnapshotFromWeb(passkeys: json([restored]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
require(try vault.loadPasskeys().count == 1, "restore ignored")
var signed = try vault.loadPasskeys()[0]
signed.counter += 1
try vault.upsert(signed)
let result = try vault.loadPasskeys()[0].toJSON()
require(result["prfKey"] as? String == "keep-prf", "native sign discarded PRF key")
require(result["updatedAt"] as? Double == 3.0, "native sign discarded restore revision")
var a = restored
a["updatedAt"] = 4.5
a["label"] = "a"
var z = a
z["label"] = "z"
for pair in [[a, z], [z, a]] {
    try archive.transaction { $0["passkeys"] = json([pair[0]]) }
    try vault.saveSnapshotFromWeb(passkeys: json([pair[1]]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
    require(try vault.loadPasskeys()[0].toJSON()["label"] as? String == "z", "equal revision depends on arrival order")
}
try vault.saveSnapshotFromWeb(passkeys: "[]", totp: nil, syncConfig: "{\"resetVault\":true}", syncDevices: nil, customRelays: nil)
require(try vault.loadPasskeys().count == 1, "config must not reset the vault")
try vault.resetVault()
require(try vault.loadPasskeys().isEmpty, "explicit reset failed")
let fixtureData = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
let fixtures = try JSONSerialization.jsonObject(with: fixtureData) as! [[String: Any]]
for fixture in fixtures {
    for first in ["local", "remote"] {
        try vault.resetVault()
        let second = first == "local" ? "remote" : "local"
        try vault.saveSnapshotFromWeb(passkeys: json([fixture[first]!]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
        try vault.saveSnapshotFromWeb(passkeys: json([fixture[second]!]), totp: nil, syncConfig: "{}", syncDevices: nil, customRelays: nil)
        let winner = try vault.loadPasskeys()[0].toJSON()
        require(winner["label"] as? String == fixture["winner"] as? String, fixture["name"] as! String)
        require(winner["counter"] as? Int == fixture["counter"] as? Int, "fixture counter floor")
        if let expected = fixture["backupEligible"] as? Bool {
            require(winner["backupEligible"] as? Bool == expected, "fixture backup flags")
        }
    }
}
let idFixturesURL = URL(fileURLWithPath: CommandLine.arguments[1])
    .deletingLastPathComponent().appendingPathComponent("credential-id-fixtures.json")
let idFixtures = try JSONSerialization.jsonObject(with: Data(contentsOf: idFixturesURL)) as! [[String: String]]
for fixture in idFixtures {
    let stored = fixture["stored"]!, expected = fixture["credentialId"]!
    require(StoredCredentialID.credentialId(stored) == expected, fixture["name"]!)
    var imported = record
    imported["id"] = stored
    imported["credentialId"] = stored
    let passkey = PasskeyRecord.fromJSON(imported)!
    require(passkey.credentialId == expected && passkey.id == stored, "load must decode \(fixture["name"]!)")
    try vault.resetVault()
    try archive.transaction { $0["passkeys"] = json([imported]) }
    require(try vault.findPasskey(credentialId: expected)?.id == stored, "lookup by decoded ID: \(fixture["name"]!)")
}
print("iOS native snapshot merge: PASS")
