import CryptoKit
import Foundation

let pair = WebAuthn.generateKeyPair()
let key = try WebAuthn.importPrivateKey(pair.privateKey)
precondition(key.publicKey.x963Representation.base64EncodedString() == pair.publicKey)
let original = Data(base64Encoded: pair.privateKey)!
var wrongTag = original
wrongTag[0] = 0x31
var wrongCurve = original
let curveOID = Data([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
let curveRange = wrongCurve.range(of: curveOID)!
wrongCurve[curveRange.upperBound - 1] = 0x08
let nakedScalar = Data([0x02, 0x01, 0x01, 0x04, 0x20]) + key.rawRepresentation
let cases = [("wrong outer tag", wrongTag), ("wrong curve", wrongCurve),
             ("unwrapped scalar", nakedScalar), ("trailing bytes", original + Data([0]))]
var accepted: [String] = []
for (name, bytes) in cases {
    do {
        _ = try WebAuthn.importPrivateKey(bytes.base64EncodedString())
        accepted.append(name)
    } catch {}
}
precondition(accepted.isEmpty, "Malformed private keys accepted: \(accepted.joined(separator: ", "))")
print("iOS private key import: PASS")
