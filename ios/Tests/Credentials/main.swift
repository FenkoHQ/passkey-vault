import CryptoKit
import Foundation

func require(_ value: Bool, _ message: String) {
    precondition(value, message)
}

func expectFailure(_ message: String, _ operation: () throws -> Void) {
    do { try operation() } catch { return }
    fatalError(message)
}

let directory = URL(fileURLWithPath: CommandLine.arguments[1])
let browserKey = try JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent("browser-key.json"))) as! [String: String]
let importedKey = try WebAuthn.importPrivateKey(browserKey["privateKey"]!)
require(importedKey.publicKey.x963Representation.base64EncodedString() == browserKey["publicKey"],
        "Browser PKCS8 import changed the key")
try importedKey.signature(for: Data("browser-key-interop".utf8)).rawRepresentation
    .write(to: directory.appendingPathComponent("browser-key-signature.bin"))
let password = "backup-test-🔑-café"
let browser = try Data(contentsOf: directory.appendingPathComponent("browser.json"))
let plaintext = try VaultBackup.decrypt(browser, password: password)
require((try JSONSerialization.jsonObject(with: plaintext) as? [String: Any])?["note"] as? String == "interop",
        "Browser backup did not decrypt")
expectFailure("Wrong password accepted") { _ = try VaultBackup.decrypt(browser, password: "wrong") }
var damaged = try JSONSerialization.jsonObject(with: browser) as! [String: Any]
var ciphertext = Data(base64Encoded: damaged["data"] as! String)!
ciphertext[0] ^= 1
damaged["data"] = ciphertext.base64EncodedString()
expectFailure("Modified ciphertext accepted") {
    _ = try VaultBackup.decrypt(JSONSerialization.data(withJSONObject: damaged), password: password)
}
try VaultBackup.encrypt(plaintext, password: password).write(to: directory.appendingPathComponent("native.json"))

let archive = VaultArchive(directory: directory.appendingPathComponent("credentials"))
try archive.unlock(key: Data(repeating: 25, count: 32))
let vault = VaultStore(archive: archive)
let user = Data("alice".utf8)
let first = try vault.register(rpId: "example.com", userName: "alice", userHandle: user, excluded: [])
let second = try vault.register(rpId: "example.com", userName: "bob", userHandle: Data("bob".utf8), excluded: [])
require(try vault.credentials(rpId: "example.com", allowed: []).count == 2, "Account choices were lost")
require(try vault.credentials(rpId: "example.com", allowed: [first.credentialID]).map(\.id) == [first.credentialID],
        "Allow list admitted another account")
require(try vault.credentials(rpId: "other.example", allowed: []).isEmpty, "RP filter admitted another site")
let before = try archive.read()
expectFailure("Excluded credential was registered again") {
    _ = try vault.register(rpId: "example.com", userName: "alice", userHandle: user, excluded: [first.credentialID])
}
require(try archive.read() == before, "Rejected registration changed records")
let hash = Data(SHA256.hash(data: Data("client data".utf8)))
expectFailure("Credential signed for another RP") {
    _ = try vault.assertion(credentialID: first.credentialID, rpId: "other.example", clientHash: hash)
}
expectFailure("Malformed client hash accepted") {
    _ = try vault.assertion(credentialID: first.credentialID, rpId: "example.com", clientHash: Data())
}
require(try archive.read() == before, "Rejected assertion changed records")
let signed = try vault.assertion(credentialID: first.credentialID, rpId: "example.com", clientHash: hash)
let record = try vault.findPasskey(credentialId: Base64URL.encode(first.credentialID))!
let publicKey = try P256.Signing.PublicKey(x963Representation: Data(base64Encoded: record.publicKey)!)
let signature = try P256.Signing.ECDSASignature(derRepresentation: signed.signature)
require(publicKey.isValidSignature(signature, for: signed.authenticatorData + hash), "Invalid assertion signature")
require(signed.userHandle == user, "Wrong user handle")
require(signed.authenticatorData.prefix(32) == Data(SHA256.hash(data: Data("example.com".utf8))), "Wrong RP hash")
require(signed.authenticatorData[32] == 0x0d, "Incorrect presence, verification or backup flags")
require(signed.authenticatorData.suffix(4) == Data([0, 0, 0, 1]), "Counter was not signed")
require(record.counter == 1, "Counter was not committed")
require(try vault.findPasskey(credentialId: Base64URL.encode(second.credentialID))!.counter == 0,
        "Another account's counter changed")
vault.lock()
expectFailure("Locked vault signed a credential") {
    _ = try vault.assertion(credentialID: first.credentialID, rpId: "example.com", clientHash: hash)
}
print("iOS passkey ceremonies: PASS")
