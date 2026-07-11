import Foundation
import CryptoKit

/// Port of the Android `WebAuthnNative` logic. Produces byte-identical
/// authenticatorData / COSE keys / attestation objects / ES256 signatures so a
/// passkey created on any Fenko Vault platform verifies the same way server-side.
enum WebAuthnError: Error {
    case missingRpId
    case badPublicKey
    case badPrivateKey
}

enum WebAuthn {
    /// Fenko Vault AAGUID d2717a32-9851-48a8-9961-b264c97a411a — must stay
    /// byte-identical to the web (cbor.ts) and Android (WebAuthnNative.java)
    /// values. See docs/aaguid/README.md.
    static let aaguid = Data([
        0xd2, 0x71, 0x7a, 0x32, 0x98, 0x51, 0x48, 0xa8,
        0x99, 0x61, 0xb2, 0x64, 0xc9, 0x7a, 0x41, 0x1a,
    ])

    // MARK: Key generation

    /// Returns (privateKey: PKCS8 base64, publicKey: raw 65-byte base64).
    static func generateKeyPair() -> (privateKey: String, publicKey: String) {
        let key = P256.Signing.PrivateKey()
        let raw = key.publicKey.x963Representation            // 0x04 || X || Y
        let pkcs8 = encodePKCS8(scalar: key.rawRepresentation, publicKey: raw)
        return (Base64Std.encode(pkcs8), Base64Std.encode(raw))
    }

    // MARK: Signing

    /// Signs `authenticatorData || clientDataHash` with ES256, returns DER signature.
    static func assertionSignature(privateKeyPKCS8B64: String,
                                   authenticatorData: Data,
                                   clientDataHash: Data) throws -> Data {
        let key = try importPrivateKey(privateKeyPKCS8B64)
        var signed = Data()
        signed.append(authenticatorData)
        signed.append(clientDataHash)
        // P256.Signing hashes with SHA-256 internally — matches "SHA256withECDSA".
        return try key.signature(for: signed).derRepresentation
    }

    static func importPrivateKey(_ b64: String) throws -> P256.Signing.PrivateKey {
        guard let der = Base64Std.decode(b64) else { throw WebAuthnError.badPrivateKey }
        let scalar = try extractP256Scalar(from: der)
        return try P256.Signing.PrivateKey(rawRepresentation: scalar)
    }

    // MARK: Authenticator data

    static func authenticatorData(rpId: String,
                                  credentialId: Data?,
                                  cosePublicKey: Data?,
                                  includeAttestedCredentialData: Bool,
                                  counter: Int) -> Data {
        var out = Data()
        out.append(sha256(Data(rpId.utf8)))
        out.append(includeAttestedCredentialData ? 0x45 : 0x05)   // flags: UP+UV(+AT)
        var be = UInt32(truncatingIfNeeded: counter).bigEndian
        out.append(Data(bytes: &be, count: 4))
        if includeAttestedCredentialData, let credentialId, let cosePublicKey {
            out.append(aaguid)
            out.append(UInt8((credentialId.count >> 8) & 0xff))
            out.append(UInt8(credentialId.count & 0xff))
            out.append(credentialId)
            out.append(cosePublicKey)
        }
        return out
    }

    static func attestationObject(authData: Data) -> Data {
        var out = Data()
        cborMap(&out, 3)
        cborText(&out, "fmt"); cborText(&out, "none")
        cborText(&out, "attStmt"); cborMap(&out, 0)
        cborText(&out, "authData"); cborBytes(&out, authData)
        return out
    }

    static func clientDataJSON(type: String, challenge: String, origin: String) -> Data {
        // Key order matches the other platforms' clientDataJSON exactly.
        let json = "{\"type\":\"\(type)\",\"challenge\":\"\(challenge)\",\"origin\":\"\(origin)\",\"crossOrigin\":false}"
        return Data(json.utf8)
    }

    /// COSE_Key (EC2, ES256) from a raw 65-byte uncompressed public key.
    static func cosePublicKey(rawPublicKey: Data) throws -> Data {
        guard rawPublicKey.count == 65, rawPublicKey.first == 0x04 else {
            throw WebAuthnError.badPublicKey
        }
        let x = rawPublicKey.subdata(in: 1..<33)
        let y = rawPublicKey.subdata(in: 33..<65)
        var out = Data()
        cborMap(&out, 5)
        cborInt(&out, 1);  cborInt(&out, 2)    // kty: EC2
        cborInt(&out, 3);  cborInt(&out, -7)   // alg: ES256
        cborInt(&out, -1); cborInt(&out, 1)    // crv: P-256
        cborInt(&out, -2); cborBytes(&out, x)  // x
        cborInt(&out, -3); cborBytes(&out, y)  // y
        return out
    }

    static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    // MARK: - Minimal CBOR (definite-length, matches the Java encoder)

    private static func cborType(_ out: inout Data, _ major: Int, _ value: Int) {
        let prefix = UInt8(major << 5)
        if value < 24 {
            out.append(prefix | UInt8(value))
        } else if value < 256 {
            out.append(prefix | 24); out.append(UInt8(value))
        } else {
            out.append(prefix | 25)
            out.append(UInt8((value >> 8) & 0xff)); out.append(UInt8(value & 0xff))
        }
    }
    private static func cborMap(_ out: inout Data, _ n: Int) { cborType(&out, 5, n) }
    private static func cborText(_ out: inout Data, _ s: String) {
        let b = Data(s.utf8); cborType(&out, 3, b.count); out.append(b)
    }
    private static func cborBytes(_ out: inout Data, _ b: Data) {
        cborType(&out, 2, b.count); out.append(b)
    }
    private static func cborInt(_ out: inout Data, _ v: Int) {
        if v >= 0 { cborType(&out, 0, v) } else { cborType(&out, 1, -1 - v) }
    }

    // MARK: - PKCS8 <-> raw P-256 (CryptoKit has no direct PKCS8 support)

    /// Extracts the 32-byte private scalar from a P-256 PKCS8 DER blob.
    /// The inner ECPrivateKey is `SEQUENCE { version 1, privateKey OCTET STRING(32), ... }`,
    /// so the scalar is uniquely anchored by the preamble `02 01 01 04 20`. Anchoring on
    /// this (rather than a bare `04 20`) avoids matching the curve coefficients that appear
    /// when a key is encoded with explicit — rather than named-curve — EC parameters.
    private static func extractP256Scalar(from der: Data) throws -> Data {
        let bytes = [UInt8](der)
        let anchor: [UInt8] = [0x02, 0x01, 0x01, 0x04, 0x20]
        var i = 0
        while i + anchor.count + 32 <= bytes.count {
            if Array(bytes[i..<(i + anchor.count)]) == anchor {
                let start = i + anchor.count
                return Data(bytes[start..<(start + 32)])
            }
            i += 1
        }
        throw WebAuthnError.badPrivateKey
    }

    /// Wraps a raw scalar + raw public key into canonical P-256 PKCS8 DER,
    /// matching WebCrypto's `exportKey('pkcs8')` output layout.
    private static func encodePKCS8(scalar: Data, publicKey: Data) -> Data {
        // ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING,
        //                             [0] parameters, [1] publicKey BIT STRING }
        var ecPrivate = Data()
        ecPrivate.append(contentsOf: [0x02, 0x01, 0x01])              // version 1
        ecPrivate.append(contentsOf: [0x04, 0x20]); ecPrivate.append(scalar)
        // [0] named curve prime256v1
        ecPrivate.append(contentsOf: [0xA0, 0x0A, 0x06, 0x08,
                                      0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
        // [1] public key BIT STRING (0 unused bits)
        var bitString = Data([0x00]); bitString.append(publicKey)
        var ctx1 = Data([0xA1]); appendLength(&ctx1, derTLV(0x03, bitString).count)
        ctx1.append(derTLV(0x03, bitString))
        ecPrivate.append(ctx1)
        let ecPrivateSeq = derTLV(0x30, ecPrivate)

        // PrivateKeyInfo ::= SEQUENCE { version 0, AlgorithmIdentifier, privateKey OCTET STRING }
        let algId = Data([
            0x30, 0x13,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,        // ecPublicKey
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,  // prime256v1
        ])
        var body = Data([0x02, 0x01, 0x00])                              // version 0
        body.append(algId)
        body.append(derTLV(0x04, ecPrivateSeq))                          // OCTET STRING
        return derTLV(0x30, body)
    }

    private static func derTLV(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag]); appendLength(&out, content.count); out.append(content); return out
    }
    private static func appendLength(_ out: inout Data, _ length: Int) {
        if length < 0x80 { out.append(UInt8(length)) }
        else if length < 0x100 { out.append(0x81); out.append(UInt8(length)) }
        else { out.append(0x82); out.append(UInt8((length >> 8) & 0xff)); out.append(UInt8(length & 0xff)) }
    }
}
