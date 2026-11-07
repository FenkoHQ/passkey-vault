import Foundation
import XCTest
@testable import VaultSync

final class DeliveryTests: XCTestCase {
    private func frame(_ id: String) -> RelayEvent {
        RelayEvent(id: id, pubkey: "fixture", createdAt: 1, kind: SyncCipher.eventKind,
                   tags: [], content: "fixture", sig: "fixture")
    }

    func testDelayedAckSurvivesRetries() throws {
        var delivery = try SyncDelivery(frames: [frame("one"), frame("two")])
        let start = Date(timeIntervalSince1970: 1)
        XCTAssertEqual(delivery.take(at: start).map(\.id), ["one", "two"])
        XCTAssertTrue(delivery.acknowledge("one"))
        XCTAssertFalse(delivery.acknowledge("unrelated"))
        XCTAssertTrue(delivery.take(at: start.addingTimeInterval(9)).isEmpty)
        XCTAssertEqual(delivery.take(at: start.addingTimeInterval(10)).map(\.id), ["two"])
        XCTAssertTrue(delivery.acknowledge("two"))
        XCTAssertEqual(delivery.state(at: start), .complete)
        XCTAssertTrue(delivery.take(at: start.addingTimeInterval(1000)).isEmpty)
    }

    func testExhaustionAndExplicitRetry() throws {
        var delivery = try SyncDelivery(frames: [frame("one")])
        let start = Date(timeIntervalSince1970: 1)
        for seconds in [0.0, 10, 30, 70, 150] {
            XCTAssertEqual(delivery.take(at: start.addingTimeInterval(seconds)).count, 1)
        }
        XCTAssertEqual(delivery.state(at: start.addingTimeInterval(269)), .pending)
        XCTAssertEqual(delivery.state(at: start.addingTimeInterval(270)), .exhausted)
        XCTAssertTrue(delivery.take(at: start.addingTimeInterval(270)).isEmpty)
        delivery.retry()
        XCTAssertEqual(delivery.take(at: start.addingTimeInterval(271)).map(\.id), ["one"])
        XCTAssertThrowsError(try SyncDelivery(frames: []))
        XCTAssertThrowsError(try SyncDelivery(frames: [frame("same"), frame("same")]))
    }
}
