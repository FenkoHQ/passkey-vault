import Foundation

var failures: [String] = []
func require(_ condition: Bool, _ message: String) {
    if !condition { failures.append(message) }
}

let secret = Data("12345678901234567890".utf8)
let base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
var canonical: [String: Any] = ["id": "otp", "type": "totp", "secretB64": secret.base64EncodedString(),
                                "issuer": "Example", "account": "alice", "algorithm": "SHA1",
                                "digits": 6, "period": 30, "counter": 0]
if let entry = TOTPEntry.fromJSON(canonical) {
    require(TOTP.code(for: entry, at: Date(timeIntervalSince1970: 59)) == "287082", "Browser TOTP code differs")
} else {
    failures.append("Canonical browser OTP secretB64 was rejected")
}
canonical.removeValue(forKey: "secretB64")
canonical["secret"] = base32
canonical["type"] = "hotp"
if let entry = TOTPEntry.fromJSON(canonical) {
    require(TOTP.code(for: entry, at: Date(timeIntervalSince1970: 59)) == "755224", "HOTP used the clock instead of its counter")
}
canonical["algorithm"] = "MD5"
let unsupported = TOTPEntry.fromJSON(canonical).flatMap { TOTP.code(for: $0) }
require(unsupported == nil, "Unsupported algorithm silently produced a SHA1 code")
precondition(failures.isEmpty, failures.joined(separator: "; "))

canonical["algorithm"] = "SHA1"
canonical["digits"] = 10
if let entry = TOTPEntry.fromJSON(canonical) {
    require(TOTP.code(for: entry, at: Date(timeIntervalSince1970: 0)) == "1284755224", "Ten-digit OTP is incompatible")
} else { failures.append("Ten-digit OTP was rejected") }
canonical["type"] = "totp"
if let entry = TOTPEntry.fromJSON(canonical) {
    require(TOTP.code(for: entry, at: Date(timeIntervalSince1970: -1)) == nil, "Pre-epoch timestamp accepted")
}
precondition(failures.isEmpty, failures.joined(separator: "; "))

let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
defer { try? FileManager.default.removeItem(at: directory) }
let archive = VaultArchive(directory: directory)
let key = Data(repeating: 19, count: 32)
try archive.unlock(key: key)
let vault = VaultStore(archive: archive)
canonical["type"] = "hotp"
canonical["digits"] = 6
canonical["updatedAt"] = 5
canonical["futureField"] = "keep"
try vault.importBackup(JSONSerialization.data(withJSONObject: ["totpEntries": [canonical]]))
let imported = try JSONSerialization.jsonObject(with: vault.syncSnapshot()) as! [String: Any]
let importedRecord = (imported["totpEntries"] as! [[String: Any]])[0]
require(try vault.items().first?.kind == .hotp && vault.items().first?.code == nil,
        "HOTP was previewed without committing its counter")
require(try vault.issueHOTP("otp") == "755224", "First HOTP issue differs from RFC 4226")
require(try vault.issueHOTP("otp") == "287082", "HOTP counter did not advance")

let peerArchive = VaultArchive(directory: directory)
try peerArchive.unlock(key: key)
let peer = VaultStore(archive: peerArchive)
let lock = NSLock()
var issued: [String] = []
DispatchQueue.concurrentPerform(iterations: 20) { index in
    let code = try! (index.isMultiple(of: 2) ? vault : peer).issueHOTP("otp")
    lock.lock()
    issued.append(code)
    lock.unlock()
}
require(Set(issued).count == 20, "Concurrent HOTP issuers reused a code")
require(try vault.loadTOTP().first?.counter == 22, "Concurrent HOTP counter advances were lost")
let snapshot = try JSONSerialization.jsonObject(with: Data(vault.snapshotJSON().utf8)) as! [String: Any]
let record = (snapshot["totpEntries"] as! [[String: Any]])[0]
require(record["updatedAt"] as? Double == importedRecord["updatedAt"] as? Double &&
        record["futureField"] as? String == "keep", "HOTP issue changed unrelated fields")
let setup = try OTPSetup.fromURI("otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example")
try vault.addOTP(setup)
let added = try vault.loadTOTP().first { $0.id != "otp" && $0.account == "alice" }!
require(TOTP.code(for: added, at: Date(timeIntervalSince1970: 59)) == "287082", "OTP setup changed the secret")
let beforeDeletion = try vault.syncSnapshot()
try vault.deleteItem(added.id, kind: .totp)
require(try !vault.loadTOTP().contains { $0.id == added.id }, "OTP deletion retained the entry")
try vault.importBackup(beforeDeletion)
require(try vault.loadTOTP().contains { $0.id == added.id }, "Explicit OTP recovery did not restore the entry")
do {
    _ = try OTPSetup.fromURI("otpauth://totp/alice?secret=AAAA&secret=BBBB")
    failures.append("OTP setup accepted duplicate secrets")
} catch {}
vault.lock()
do {
    _ = try vault.issueHOTP("otp")
    failures.append("Locked vault issued an HOTP code")
} catch {}
precondition(failures.isEmpty, failures.joined(separator: "; "))
print("iOS OTP compatibility: PASS")
