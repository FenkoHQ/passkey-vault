import CoreFoundation
import Foundation

public struct RelaySyncConfig: Sendable {
    public let seedHash: String
    public let deviceID: String
    public let deviceName: String
    public let relays: [URL]

    public init(seedHash: String, deviceID: String, deviceName: String, relays: [URL]) throws {
        guard Data(hex: seedHash)?.count == 32, !deviceID.isEmpty, !relays.isEmpty,
              relays.allSatisfy({ $0.scheme == "wss" && $0.host != nil && $0.user == nil && $0.fragment == nil }) else {
            throw SyncError.invalidMessage
        }
        self.seedHash = seedHash
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.relays = relays
    }
}

public enum SyncStatus: Sendable, Equatable {
    case stopped, connecting, connected, sent, received, retryNeeded, networkError, storageError
}

public enum SyncChange: Sendable {
    case unchanged, changed
}

public actor SyncService {
    public typealias Load = @Sendable () async throws -> Data
    public typealias Apply = @Sendable (SyncIncoming) async throws -> SyncChange
    public typealias Report = @Sendable (SyncStatus) async -> Void
    private static let reconnectDelay: Duration = .seconds(5)
    private static let tickDelay: Duration = .seconds(1)
    private static let sendInterval: TimeInterval = 10
    private static let heartbeat: TimeInterval = 300
    private let config: RelaySyncConfig
    private let load: Load
    private let apply: Apply
    private let report: Report
    private let connect: @Sendable (URL) -> any RelayConnection
    private var worker: Task<Void, Never>?
    private var pump: Task<Void, Never>?
    private var socket: (any RelayConnection)?
    private var wire: SyncProtocol?
    private var generation = 0
    private var link = 0
    private var dirty = true
    private var revision = 0
    private var lastSnapshot = Date.distantPast
    private var deliveries: [SyncIncoming.Kind: SyncDelivery] = [:]

    public init(config: RelaySyncConfig, load: @escaping Load, apply: @escaping Apply, report: @escaping Report) {
        self.config = config
        self.load = load
        self.apply = apply
        self.report = report
        connect = { URLRelayConnection(url: $0) }
    }

    init(config: RelaySyncConfig, load: @escaping Load, apply: @escaping Apply, report: @escaping Report,
         connect: @escaping @Sendable (URL) -> any RelayConnection) {
        self.config = config
        self.load = load
        self.apply = apply
        self.report = report
        self.connect = connect
    }

    public func start() {
        guard worker == nil else { return }
        generation += 1
        let token = generation
        worker = Task { await run(token: token) }
    }

    public func stop() async {
        generation += 1
        let token = generation
        link += 1
        worker?.cancel()
        pump?.cancel()
        worker = nil
        pump = nil
        let previous = socket
        socket = nil
        wire = nil
        deliveries.removeAll()
        dirty = true
        await previous?.close()
        if generation == token { await report(.stopped) }
    }

    public func changed() {
        revision += 1
        dirty = true
    }

    public func retry() {
        for kind in Array(deliveries.keys) { deliveries[kind]?.retry() }
        changed()
    }

    private func current(_ token: Int, _ connection: Int) -> Bool {
        generation == token && link == connection && !Task.isCancelled
    }

    private func run(token: Int) async {
        do {
            wire = try SyncProtocol(seedHash: config.seedHash, deviceID: config.deviceID, deviceName: config.deviceName)
        } catch {
            await report(.storageError)
            if generation == token { worker = nil }
            return
        }
        var relay = 0
        while generation == token && !Task.isCancelled {
            link += 1
            let connection = link
            let channel = connect(config.relays[relay % config.relays.count])
            socket = channel
            await report(.connecting)
            do {
                guard current(token, connection), let wire else { break }
                try await channel.send(wire.subscription())
                guard current(token, connection) else { break }
                await report(.connected)
                guard current(token, connection) else { break }
                deliveries.removeAll()
                try enqueue(wire.announce(), kind: .announce)
                try enqueue(wire.request(), kind: .request)
                dirty = true
                lastSnapshot = .distantPast
                pump = Task { await tick(channel, token: token, connection: connection) }
                while current(token, connection) {
                    let frame = try await channel.receive()
                    guard current(token, connection) else { break }
                    do {
                        try await handle(frame, channel: channel, token: token, connection: connection)
                    } catch is CancellationError { break }
                    catch {
                        // Malformed remote messages cannot tear down a healthy relay connection.
                        continue
                    }
                }
            } catch {
                if current(token, connection) { await report(.networkError) }
            }
            guard generation == token && link == connection else {
                await channel.close()
                return
            }
            pump?.cancel()
            pump = nil
            await channel.close()
            guard current(token, connection) else { return }
            socket = nil
            wire?.resetChunks()
            relay += 1
            do { try await Task.sleep(for: Self.reconnectDelay) } catch { return }
        }
    }

    private func tick(_ channel: any RelayConnection, token: Int, connection: Int) async {
        while current(token, connection) {
            do {
                let now = Date()
                let elapsed = now.timeIntervalSince(lastSnapshot)
                if (dirty && elapsed >= Self.sendInterval) || elapsed >= Self.heartbeat {
                    do {
                        let snapshotRevision = revision
                        let snapshot = try await load()
                        guard current(token, connection), let wire else { return }
                        try enqueue(wire.snapshot(snapshot, purpose: .update), kind: .update)
                        if elapsed >= Self.heartbeat { try enqueue(wire.request(), kind: .request) }
                        dirty = revision != snapshotRevision
                        lastSnapshot = now
                    } catch {
                        guard current(token, connection) else { return }
                        await report(.storageError)
                        lastSnapshot = now
                    }
                }
                for kind in [SyncIncoming.Kind.announce, .request, .update, .response] {
                    guard current(token, connection), var delivery = deliveries[kind] else { continue }
                    if delivery.state() == .exhausted { await report(.retryNeeded) }
                    let events = delivery.take()
                    deliveries[kind] = delivery
                    for event in events {
                        guard current(token, connection) else { return }
                        try await channel.send(SyncProtocol.publishFrame(event))
                    }
                }
                try await Task.sleep(for: Self.tickDelay)
            } catch {
                if current(token, connection) {
                    await report(.networkError)
                    await channel.close()
                }
                return
            }
        }
    }

    private func enqueue(_ events: [RelayEvent], kind: SyncIncoming.Kind) throws {
        deliveries[kind] = try SyncDelivery(frames: events)
    }

    private func handle(_ raw: String, channel: any RelayConnection, token: Int, connection: Int) async throws {
        guard raw.utf8.count <= RelayLimits.maxFrameBytes,
              let frame = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [Any],
              let type = frame.first as? String else { throw SyncError.invalidMessage }
        if type == "OK" {
            guard frame.count >= 3, let id = frame[1] as? String, let accepted = frame[2] as? NSNumber,
                  CFGetTypeID(accepted) == CFBooleanGetTypeID() else { throw SyncError.invalidMessage }
            guard accepted.boolValue else { await report(.retryNeeded); return }
            for kind in Array(deliveries.keys) {
                guard current(token, connection) else { return }
                guard var delivery = deliveries[kind], delivery.acknowledge(id) else { continue }
                if delivery.state() == .complete {
                    deliveries.removeValue(forKey: kind)
                    if kind == .update || kind == .response { await report(.sent) }
                } else {
                    deliveries[kind] = delivery
                }
            }
            return
        }
        if type == "EOSE", frame.count > 1, let subscription = frame[1] as? String,
           subscription.hasPrefix("parts_") {
            let close = try JSONSerialization.data(withJSONObject: ["CLOSE", subscription])
            try await channel.send(String(decoding: close, as: UTF8.self))
            return
        }
        guard type == "EVENT", frame.count == 3, let wire else { return }
        let event = try JSONDecoder().decode(RelayEvent.self, from: JSONSerialization.data(withJSONObject: frame[2]))
        switch try wire.receive(event) {
        case .ignored: return
        case .missing(let requests):
            for request in requests {
                guard current(token, connection) else { return }
                try await channel.send(request)
            }
        case .message(let message):
            let change: SyncChange
            do { change = try await apply(message) }
            catch {
                if current(token, connection) { await report(.storageError) }
                return
            }
            guard current(token, connection) else { return }
            if message.kind == .request, let requestID = message.requestID {
                let snapshot = try await load()
                guard current(token, connection) else { return }
                try enqueue(wire.snapshot(snapshot, purpose: .response(requestID: requestID)), kind: .response)
            }
            wire.committed(message.eventID)
            if message.snapshot != nil {
                if change == .changed { changed() }
                await report(.received)
            }
        }
    }
}
