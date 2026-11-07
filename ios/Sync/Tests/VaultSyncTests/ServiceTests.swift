import Foundation
import Security
import XCTest
@testable import VaultSync

private actor TestRelay: RelayConnection {
    private var frames: [String] = []
    private var incoming: [String] = []
    private var reader: CheckedContinuation<String, any Error>?
    private var closed = false

    func send(_ text: String) async throws {
        guard !closed else { throw CancellationError() }
        frames.append(text)
        let frame = try JSONSerialization.jsonObject(with: Data(text.utf8)) as! [Any]
        if frame.first as? String == "EVENT", let event = frame[1] as? [String: Any], let id = event["id"] as? String {
            let ack = try JSONSerialization.data(withJSONObject: ["OK", id, true, ""])
            push(String(decoding: ack, as: UTF8.self))
        }
    }

    func receive() async throws -> String {
        guard !closed else { throw CancellationError() }
        if !incoming.isEmpty { return incoming.removeFirst() }
        return try await withCheckedThrowingContinuation { reader = $0 }
    }

    func push(_ text: String) {
        guard !closed else { return }
        if let reader {
            self.reader = nil
            reader.resume(returning: text)
        } else {
            incoming.append(text)
        }
    }

    func close() async {
        closed = true
        reader?.resume(throwing: CancellationError())
        reader = nil
    }

    func sentFrames() -> [String] { frames }
}

private actor TestSyncStorage {
    private var statuses: [SyncStatus] = []
    private var applied: [String] = []
    private var attempts = 0
    private var failures = 0
    private var hold = false
    private var pending: CheckedContinuation<Data, Never>?
    private let snapshot: Data
    private var received: [Data] = []

    init(snapshot: Data = Data("{\"passkeys\":[],\"totpEntries\":[]}".utf8)) {
        self.snapshot = snapshot
    }

    func load() async -> Data {
        if hold { return await withCheckedContinuation { pending = $0 } }
        return snapshot
    }

    func apply(_ message: SyncIncoming) throws -> SyncChange {
        attempts += 1
        if failures > 0 {
            failures -= 1
            throw SyncError.invalidMessage
        }
        applied.append(message.eventID)
        if let snapshot = message.snapshot { received.append(snapshot) }
        return .unchanged
    }

    func report(_ status: SyncStatus) { statuses.append(status) }
    func hasStatus(_ status: SyncStatus) -> Bool { statuses.contains(status) }
    func failureCount(_ count: Int) { failures = count }
    func holdLoad() { hold = true }
    func waiting() -> Bool { pending != nil }
    func appliedCount() -> Int { applied.count }
    func attemptCount() -> Int { attempts }
    func hasCredential(_ id: String) -> Bool {
        received.contains { data in
            guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let passkeys = object["passkeys"] as? [[String: Any]] else { return false }
            return passkeys.contains { $0["id"] as? String == id }
        }
    }
    func release() {
        hold = false
        pending?.resume(returning: snapshot)
        pending = nil
    }
}

// Test-only trust anchor; hostname and certificate validation still run.
private final class TestTrustDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let certificate: Data
    init(certificate: Data) { self.certificate = certificate }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host == "localhost",
              let trust = challenge.protectionSpace.serverTrust,
              let certificate = SecCertificateCreateWithData(nil, certificate as CFData),
              SecTrustSetAnchorCertificates(trust, [certificate] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

private final class TestTLSConnection: RelayConnection {
    private let base: URLRelayConnection
    init(url: URL, session: URLSession) { base = URLRelayConnection(url: url, session: session) }
    func send(_ text: String) async throws {
        do { try await base.send(text) }
        catch {
            print("Local TLS send failed: \(error)")
            throw error
        }
    }
    func receive() async throws -> String {
        do { return try await base.receive() }
        catch {
            print("Local TLS receive failed: \(error)")
            throw error
        }
    }
    func close() async { await base.close() }
}

@MainActor
final class ServiceTests: XCTestCase {
    private func config() throws -> RelaySyncConfig {
        try RelaySyncConfig(seedHash: String(repeating: "ab", count: 32), deviceID: "native", deviceName: "iPhone",
                            relays: [URL(string: "wss://relay.example")!])
    }

    private func service(_ relay: TestRelay, _ storage: TestSyncStorage) throws -> SyncService {
        try SyncService(config: config(), load: { await storage.load() },
                        apply: { try await storage.apply($0) }, report: { await storage.report($0) },
                        connect: { _ in relay })
    }

    private func eventually(_ check: @escaping @Sendable () async -> Bool) async throws {
        for _ in 0..<150 {
            if await check() { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTFail("Timed out waiting for native sync")
    }

    func testPublishesAndAcceptsRelayAck() async throws {
        let relay = TestRelay()
        let storage = TestSyncStorage()
        let service = try service(relay, storage)
        await service.start()
        try await eventually { await storage.hasStatus(.sent) }
        let frames = await relay.sentFrames()
        XCTAssertTrue(frames.contains { $0.contains("REQ") })
        XCTAssertTrue(frames.contains { $0.contains("EVENT") })
        await service.stop()
        let stopped = await storage.hasStatus(.stopped)
        XCTAssertTrue(stopped)
    }

    func testLockDropsPendingSnapshot() async throws {
        let relay = TestRelay()
        let storage = TestSyncStorage()
        await storage.holdLoad()
        let service = try service(relay, storage)
        await service.start()
        try await eventually { await storage.waiting() }
        await service.stop()
        let before = await relay.sentFrames()
        await storage.release()
        try await Task.sleep(for: .milliseconds(100))
        let after = await relay.sentFrames()
        XCTAssertEqual(before, after, "A snapshot was sent after lock")
        XCTAssertFalse(after.contains { $0.contains("EVENT") })
    }

    func testStorageFailureCanReplay() async throws {
        let relay = TestRelay()
        let storage = TestSyncStorage()
        await storage.failureCount(1)
        let service = try service(relay, storage)
        await service.start()
        try await eventually { await storage.hasStatus(.sent) }
        let sender = try SyncProtocol(seedHash: config().seedHash, deviceID: "peer", deviceName: "Browser")
        let event = try XCTUnwrap(sender.snapshot(Data("{\"passkeys\":[],\"totpEntries\":[]}".utf8), purpose: .update).first)
        let eventObject = try JSONSerialization.jsonObject(with: SyncJSON.encode(event))
        let frame = String(decoding: try JSONSerialization.data(withJSONObject: ["EVENT", "subscription", eventObject]), as: UTF8.self)
        await relay.push(frame)
        try await eventually { await storage.attemptCount() == 1 }
        let initiallyApplied = await storage.appliedCount()
        XCTAssertEqual(initiallyApplied, 0)
        await relay.push(frame)
        try await eventually { await storage.appliedCount() == 1 }
        await relay.push(frame)
        try await Task.sleep(for: .milliseconds(100))
        let attempts = await storage.attemptCount()
        XCTAssertEqual(attempts, 2, "Committed event was applied again")
        await service.stop()
    }

    func testTwoClientsOverTLS() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let address = environment["SYNC_TEST_RELAY"], let url = URL(string: address),
              let path = environment["SYNC_TEST_CERT"] else {
            throw XCTSkip("Local TLS relay is not configured")
        }
        let trust = TestTrustDelegate(certificate: try Data(contentsOf: URL(fileURLWithPath: path)))
        let open: @Sendable (URL) -> any RelayConnection = { url in
            let session = URLSession(configuration: .ephemeral, delegate: trust, delegateQueue: nil)
            return TestTLSConnection(url: url, session: session)
        }
        let firstStore = TestSyncStorage(snapshot: Data("{\"passkeys\":[{\"id\":\"native-tls-credential\"}],\"totpEntries\":[]}".utf8))
        let secondStore = TestSyncStorage()
        let hash = try SyncRecovery.seedHash(SyncRecovery.generate())
        let firstConfig = try RelaySyncConfig(seedHash: hash, deviceID: "one", deviceName: "Phone one", relays: [url])
        let secondConfig = try RelaySyncConfig(seedHash: hash, deviceID: "two", deviceName: "Phone two", relays: [url])
        let first = SyncService(config: firstConfig, load: { await firstStore.load() },
                                apply: { try await firstStore.apply($0) }, report: { await firstStore.report($0) }, connect: open)
        let second = SyncService(config: secondConfig, load: { await secondStore.load() },
                                 apply: { try await secondStore.apply($0) }, report: { await secondStore.report($0) }, connect: open)
        await first.start()
        await second.start()
        try await eventually { await secondStore.hasCredential("native-tls-credential") }
        let accepted = await firstStore.hasStatus(.sent)
        XCTAssertTrue(accepted, "The independent relay did not accept the native signature")
        await first.stop()
        await second.stop()
    }
}
