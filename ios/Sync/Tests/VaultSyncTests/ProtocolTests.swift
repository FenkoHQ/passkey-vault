import Foundation
import XCTest
@testable import VaultSync

final class ProtocolTests: XCTestCase {
    private let seed = String(repeating: "ab", count: 32)

    func testChunkedSnapshotCommitsAfterStorage() throws {
        let sender = try SyncProtocol(seedHash: seed, deviceID: "one", deviceName: "First phone")
        let receiver = try SyncProtocol(seedHash: seed, deviceID: "two", deviceName: "Second phone")
        let source: [String: Any] = [
            "passkeys": [["id": "credential", "privateKey": String(repeating: "test-key", count: 6000)]],
            "totpEntries": [], "deletions": [["id": "deleted", "kind": "passkey", "deletedAt": 1]],
            "syncConfig": ["seedHash": "local-only-key"],
        ]
        let events = try sender.snapshot(JSONSerialization.data(withJSONObject: source), purpose: .update)
        XCTAssertGreaterThan(events.count, 1)
        var received: SyncIncoming?
        var final: RelayEvent?
        for event in events.reversed() {
            XCTAssertLessThanOrEqual(try SyncProtocol.publishFrame(event).utf8.count, SyncCipher.maxEventBytes)
            if case .message(let message) = try receiver.receive(event) {
                received = message
                final = event
            }
        }
        let message = try XCTUnwrap(received)
        XCTAssertEqual(message.kind, .update)
        XCTAssertEqual(message.peer.id, "one")
        let snapshot = try XCTUnwrap(message.snapshot)
        let decoded = try JSONSerialization.jsonObject(with: snapshot) as! [String: Any]
        XCTAssertEqual((decoded["passkeys"] as? [[String: Any]])?.first?["id"] as? String, "credential")
        XCTAssertEqual((decoded["deletions"] as? [[String: Any]])?.first?["id"] as? String, "deleted")
        XCTAssertFalse(String(decoding: snapshot, as: UTF8.self).contains("local-only-key"))
        guard case .message = try receiver.receive(XCTUnwrap(final)) else {
            return XCTFail("A failed storage write cannot retry its event")
        }
        receiver.committed(message.eventID)
        guard case .ignored = try receiver.receive(XCTUnwrap(final)) else {
            return XCTFail("A committed event was applied twice")
        }
    }

    func testRequestResponseAndIsolation() throws {
        let sender = try SyncProtocol(seedHash: seed, deviceID: "one", deviceName: "First phone")
        let receiver = try SyncProtocol(seedHash: seed, deviceID: "two", deviceName: "Second phone")
        let other = try SyncProtocol(seedHash: String(repeating: "cd", count: 32), deviceID: "three", deviceName: "Other chain")
        let request = try XCTUnwrap(sender.request().first)
        guard case .ignored = try sender.receive(request) else { return XCTFail("Applied own event") }
        guard case .ignored = try other.receive(request) else { return XCTFail("Accepted another chain's event") }
        guard case .message(let message) = try receiver.receive(request) else { return XCTFail("Lost request") }
        XCTAssertEqual(message.kind, .request)
        let requestID = try XCTUnwrap(message.requestID)
        let response = try XCTUnwrap(receiver.snapshot(Data("{\"passkeys\":[],\"totpEntries\":[]}".utf8),
                                                        purpose: .response(requestID: requestID)).first)
        guard case .message(let reply) = try sender.receive(response) else { return XCTFail("Lost response") }
        XCTAssertEqual(reply.kind, .response)
        XCTAssertEqual(reply.requestID, requestID)
        XCTAssertNotNil(reply.snapshot)
        XCTAssertThrowsError(try receiver.snapshot(Data("{\"passkeys\":\"bad\"}".utf8), purpose: .update))
    }
}
