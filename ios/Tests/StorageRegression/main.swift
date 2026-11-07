import Foundation

let suite = "nz.fenko.storage-regression.\(UUID().uuidString)"
let defaults = UserDefaults(suiteName: suite)!
defer { defaults.removePersistentDomain(forName: suite) }
let vault = VaultStore(suiteName: suite)
let record: [String: Any] = [
    "id": "credential", "credentialId": "Y3JlZGVudGlhbA", "rpId": "example.com",
    "privateKey": "storage-regression-private-key", "publicKey": "public-key",
    "createdAt": 1.0, "counter": 0,
]
vault.savePasskeys([PasskeyRecord.fromJSON(record)!])

// Saving a credential must not leave its private key in shared preferences.
let stored = defaults.dictionaryRepresentation().description
precondition(!stored.contains("storage-regression-private-key"),
             "Private keys remain readable in shared UserDefaults")
print("iOS encrypted storage: PASS")
