import CryptoKit
import Foundation
import XCTest
@testable import VaultSync

final class SyncTests: XCTestCase {
    private struct Fixture: Decodable {
        let entropy: String
        let phrase: String
        let seedHash: String
        let chainID: String
        let author: String
        let plaintext: String
        let event: RelayEvent
    }

    private func fixture() throws -> Fixture {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "browser-sync", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    }

    func testRecoveryCompatibility() throws {
        let fixture = try fixture()
        XCTAssertEqual(try SyncRecovery.decode(fixture.phrase).hex, fixture.entropy)
        XCTAssertEqual(try SyncRecovery.encode(Data(hex: fixture.entropy)!), fixture.phrase)
        XCTAssertEqual(try SyncRecovery.seedHash(fixture.phrase), fixture.seedHash)
        let extended = "school zero lens rule swift jeans afraid hand guilt estate vicious teach " +
            "pizza coffee hat enter foil sport notable regret pizza coffee hat flag"
        XCTAssertEqual(try SyncRecovery.decode(extended).hex,
                       "c0ffee00deadbeef0123456789abcdef5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
        XCTAssertEqual(try SyncRecovery.encode(SyncRecovery.decode(extended)), extended)
        XCTAssertThrowsError(try SyncRecovery.decode("abandon"))
        XCTAssertThrowsError(try SyncRecovery.decode(Array(repeating: "not-a-word", count: 12).joined(separator: " ")))
        XCTAssertThrowsError(try SyncRecovery.encode(Data(repeating: 255, count: 16)))
        for length in [SyncRecovery.Length.standard, .extended] {
            for _ in 0..<100 {
                let phrase = try SyncRecovery.generate(length: length)
                XCTAssertEqual(phrase.split(separator: " ").count, length.rawValue)
                XCTAssertEqual(try SyncRecovery.encode(SyncRecovery.decode(phrase)), phrase)
            }
        }
    }

    func testBrowserMessageAndSignature() throws {
        let fixture = try fixture()
        let cipher = try SyncCipher(seedHash: fixture.seedHash)
        XCTAssertEqual(cipher.chainID, fixture.chainID)
        XCTAssertEqual(cipher.author, fixture.author)
        XCTAssertTrue(cipher.verify(fixture.event))
        XCTAssertEqual(try cipher.decryptMessage(fixture.event.content), Data(fixture.plaintext.utf8))
        let signed = try cipher.sign(content: fixture.event.content, tags: fixture.event.tags,
                                     createdAt: fixture.event.createdAt)
        XCTAssertEqual(signed.id, fixture.event.id, "Canonical event JSON differs from the browser")
        XCTAssertTrue(cipher.verify(signed))
        let wrong = try SyncCipher(seedHash: String(repeating: "ab", count: 32))
        XCTAssertFalse(wrong.verify(signed))
        XCTAssertThrowsError(try wrong.decryptMessage(signed.content))
        let changed = RelayEvent(id: signed.id, pubkey: signed.pubkey, createdAt: signed.createdAt,
                                  kind: signed.kind, tags: signed.tags, content: signed.content + " ", sig: signed.sig)
        XCTAssertFalse(cipher.verify(changed))
        let forged = RelayEvent(id: signed.id, pubkey: signed.pubkey, createdAt: signed.createdAt,
                                 kind: signed.kind, tags: signed.tags, content: signed.content,
                                 sig: String(repeating: "00", count: 64))
        XCTAssertFalse(cipher.verify(forged))
    }

    func testCipherBoundsAndTampering() throws {
        let cipher = try SyncCipher(seedHash: fixture().seedHash)
        let data = Data("native sync".utf8)
        let first = try cipher.encryptMessage(data)
        let second = try cipher.encryptMessage(data)
        XCTAssertNotEqual(first, second, "AES-GCM nonce was reused")
        XCTAssertEqual(try cipher.decryptMessage(first), data)
        let box = try cipher.seal(data)
        var damaged = Data(base64Encoded: box.ciphertext)!
        damaged[0] ^= 1
        XCTAssertThrowsError(try cipher.open(SyncBox(nonce: box.nonce, ciphertext: damaged.base64EncodedString())))
        XCTAssertThrowsError(try cipher.open(SyncBox(nonce: "", ciphertext: box.ciphertext)))
        XCTAssertThrowsError(try cipher.sign(content: String(repeating: "x", count: SyncCipher.maxEventBytes),
                                             tags: [], createdAt: 1))
        XCTAssertThrowsError(try SyncCipher(seedHash: "bad-key"))
    }

    func testRelayCapacityUsesWireJSON() throws {
        let cipher = try SyncCipher(seedHash: fixture().seedHash)
        // JSON.stringify leaves slashes literal; base64 can contain many of them.
        let signed = try cipher.sign(content: String(repeating: "/", count: 12_000), tags: [], createdAt: 1)
        XCTAssertTrue(cipher.verify(signed))
    }
}
