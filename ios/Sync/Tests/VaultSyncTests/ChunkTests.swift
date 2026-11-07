import Foundation
import XCTest
@testable import VaultSync

final class ChunkTests: XCTestCase {
    func testOutOfOrderAndWriteRetry() throws {
        let payload = "{\"c\":\"" + String(repeating: "abcdef", count: 5000) + "\"}"
        let parts = try SyncChunks.split(payload)
        XCTAssertEqual(parts.count, 3)
        let collector = SyncChunks()
        XCTAssertNil(try collector.accept(parts[2]))
        XCTAssertNil(try collector.accept(parts[0]))
        XCTAssertNil(try collector.accept(parts[0]))
        XCTAssertEqual(try collector.accept(parts[1]), payload)
        XCTAssertEqual(try collector.accept(parts[1]), payload, "Retry after storage failure lost the completed payload")
        let requests = try collector.missing(parts[2], address: "pksync-v4-chain-device-update-2", author: String(repeating: "ab", count: 32))
        XCTAssertEqual(requests.count, 1)
        let frame = try JSONSerialization.jsonObject(with: Data(requests[0].utf8)) as! [Any]
        let filter = frame[2] as! [String: Any]
        XCTAssertEqual(filter["#d"] as? [String], (0..<3).map { "pksync-v4-chain-device-update-\($0)" })
        XCTAssertTrue(try collector.missing(parts[2], address: "pksync-v4-chain-device-update-2",
                                             author: String(repeating: "ab", count: 32)).isEmpty)
    }

    func testRejectsConflictsAndTampering() throws {
        let parts = try SyncChunks.split(String(repeating: "a", count: 24_001))
        let collector = SyncChunks()
        XCTAssertNil(try collector.accept(parts[0]))
        var object = try JSONSerialization.jsonObject(with: Data(parts[0].utf8)) as! [String: Any]
        object["data"] = "changed"
        let changed = String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
        XCTAssertThrowsError(try collector.accept(changed))
        object["total"] = 1401
        XCTAssertThrowsError(try collector.accept(String(decoding: JSONSerialization.data(withJSONObject: object), as: UTF8.self)))
        object["total"] = 3
        object["index"] = 1
        XCTAssertNil(try collector.accept(String(decoding: JSONSerialization.data(withJSONObject: object), as: UTF8.self)))
        XCTAssertThrowsError(try collector.accept(parts[2]), "Digest mismatch was accepted")
        XCTAssertThrowsError(try SyncChunks.split(String(repeating: "x", count: 16_800_001)))
    }

    func testExpiredPartsAreDiscarded() throws {
        let parts = try SyncChunks.split(String(repeating: "a", count: 12_001))
        let collector = SyncChunks()
        let start = Date(timeIntervalSince1970: 1)
        XCTAssertNil(try collector.accept(parts[0], at: start))
        XCTAssertNil(try collector.accept(parts[1], at: start.addingTimeInterval(1801)))
        XCTAssertNotNil(try collector.accept(parts[0], at: start.addingTimeInterval(1802)))
        collector.reset()
        XCTAssertNil(try collector.accept(parts[1]))
    }
}
