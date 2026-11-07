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
print("iOS OTP compatibility: PASS")
