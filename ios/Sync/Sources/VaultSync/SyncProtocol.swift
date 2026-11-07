import Foundation

public struct SyncPeer: Sendable {
    public let id: String
    public let name: String
    public let type: String
    public let lastSeen: Double
}

public struct SyncIncoming: Sendable {
    public enum Kind: String, Sendable {
        case announce, request, update, response
    }
    public let kind: Kind
    public let peer: SyncPeer
    public let eventID: String
    public let requestID: String?
    public let snapshot: Data?
}

public enum SyncReception: Sendable {
    case ignored
    case missing([String])
    case message(SyncIncoming)
}

// Owns wire compatibility and replay tracking; persistence decides when an event is committed.
public final class SyncProtocol {
    public enum SnapshotPurpose {
        case update
        case response(requestID: String)
    }

    private static let maxProcessed = 1000
    private static let lookback: TimeInterval = 3600
    private static let maxIdentityBytes = 256
    private let cipher: SyncCipher
    private let deviceID: String
    private let deviceName: String
    private let chunks = SyncChunks()
    private var sequence = 0
    private var processed: Set<String> = []
    private var order: [String] = []

    public init(seedHash: String, deviceID: String, deviceName: String) throws {
        guard !deviceID.isEmpty, deviceID.utf8.count <= Self.maxIdentityBytes,
              deviceName.utf8.count <= Self.maxIdentityBytes else { throw SyncError.invalidMessage }
        cipher = try SyncCipher(seedHash: seedHash)
        self.deviceID = deviceID
        self.deviceName = deviceName
    }

    public func subscription(at now: Date = Date()) throws -> String {
        let filters: [[String: Any]] = [
            ["kinds": [SyncCipher.eventKind], "#d": ["pksync-v4-\(cipher.chainID)"],
             "since": Int64(now.timeIntervalSince1970 - Self.lookback), "limit": 50],
            ["kinds": [SyncCipher.eventKind], "authors": [cipher.author], "#h": [cipher.chainID]],
        ]
        return try string(["REQ", "ios_\(deviceID)"] + filters.map { $0 as Any })
    }

    public func announce(at now: Date = Date()) throws -> [RelayEvent] {
        try events(kind: .announce, payload: ["action": "online"], at: now)
    }

    public func request(at now: Date = Date()) throws -> [RelayEvent] {
        try events(kind: .request, payload: ["action": "sync", "requestId": UUID().uuidString], at: now)
    }

    public func snapshot(_ data: Data, purpose: SnapshotPurpose, at now: Date = Date()) throws -> [RelayEvent] {
        let object = try dictionary(data)
        let passkeys = try records(object, "passkeys")
        let totp = try records(object, "totpEntries")
        let deletions = try records(object, "deletions")
        let time = now.timeIntervalSince1970 * 1000
        // Select credential fields explicitly; device-local settings and keys never enter the bundle.
        let payload: [String: Any] = ["passkeys": passkeys, "totpEntries": totp, "deletions": deletions,
                                      "passkeyIds": passkeys.compactMap { $0["id"] as? String },
                                      "totpIds": totp.compactMap { $0["id"] as? String },
                                      "timestamp": time, "deviceId": deviceID]
        let box = try cipher.seal(JSONSerialization.data(withJSONObject: payload))
        let bundle: [String: Any] = ["version": SyncCipher.version, "deviceId": deviceID, "timestamp": time,
                                     "nonce": box.nonce, "ciphertext": box.ciphertext,
                                     "passkeyCount": passkeys.count, "totpCount": totp.count]
        switch purpose {
        case .update:
            return try events(kind: .update, payload: ["bundle": bundle], at: now)
        case .response(let requestID):
            return try events(kind: .response, payload: ["bundle": bundle, "requestId": requestID], at: now)
        }
    }

    public func receive(_ event: RelayEvent, at now: Date = Date()) throws -> SyncReception {
        guard !processed.contains(event.id), cipher.verify(event) else { return .ignored }
        guard let content = try chunks.accept(event.content, at: now) else {
            let address = event.tags.first(where: { $0.first == "d" }).flatMap { $0.count > 1 ? $0[1] : nil } ?? ""
            guard address.hasPrefix("pksync-v4-\(cipher.chainID)-") else { throw SyncError.invalidMessage }
            return .missing(try chunks.missing(event.content, address: address, author: event.pubkey))
        }
        let message = try dictionary(cipher.decryptMessage(content))
        guard message["chainId"] as? String == cipher.chainID,
              let sender = message["deviceId"] as? String, sender != deviceID,
              !sender.isEmpty, sender.utf8.count <= Self.maxIdentityBytes,
              let type = message["type"] as? String, let kind = SyncIncoming.Kind(rawValue: type),
              let time = message["timestamp"] as? Double, time.isFinite, time >= 0,
              let payload = message["payload"] as? [String: Any] else { return .ignored }
        let name = message["deviceName"] as? String ?? "Other device"
        let deviceType = message["deviceType"] as? String ?? "Unknown"
        guard name.utf8.count <= Self.maxIdentityBytes, deviceType.utf8.count <= Self.maxIdentityBytes else {
            throw SyncError.invalidMessage
        }
        let peer = SyncPeer(id: sender, name: name, type: deviceType, lastSeen: time)
        var snapshot: Data?
        if kind == .update || kind == .response {
            guard let bundle = payload["bundle"] as? [String: Any],
                  bundle["version"] as? String == SyncCipher.version, bundle["deviceId"] as? String == sender,
                  let nonce = bundle["nonce"] as? String, let ciphertext = bundle["ciphertext"] as? String else {
                throw SyncError.invalidMessage
            }
            let decoded = try dictionary(cipher.open(SyncBox(nonce: nonce, ciphertext: ciphertext)))
            guard decoded["deviceId"] as? String == sender else { throw SyncError.invalidMessage }
            snapshot = try JSONSerialization.data(withJSONObject: [
                "passkeys": records(decoded, "passkeys"), "totpEntries": records(decoded, "totpEntries"),
                "deletions": records(decoded, "deletions"),
            ])
        }
        if kind == .request, payload["action"] as? String != "sync" { return .ignored }
        let requestID = payload["requestId"] as? String
        if kind == .request, requestID == nil || requestID!.utf8.count > Self.maxIdentityBytes {
            throw SyncError.invalidMessage
        }
        return .message(SyncIncoming(kind: kind, peer: peer, eventID: event.id,
                                     requestID: requestID, snapshot: snapshot))
    }

    public func committed(_ id: String) {
        guard processed.insert(id).inserted else { return }
        order.append(id)
        if order.count > Self.maxProcessed { processed.remove(order.removeFirst()) }
    }

    public func resetChunks() {
        chunks.reset()
    }

    public static func publishFrame(_ event: RelayEvent) throws -> String {
        let object = try JSONSerialization.jsonObject(with: SyncJSON.encode(event))
        let data = try JSONSerialization.data(withJSONObject: ["EVENT", object], options: [.withoutEscapingSlashes])
        guard data.count <= SyncCipher.maxEventBytes else { throw SyncError.capacity }
        return String(decoding: data, as: UTF8.self)
    }

    private func events(kind: SyncIncoming.Kind, payload: [String: Any], at now: Date) throws -> [RelayEvent] {
        sequence += 1
        let message: [String: Any] = ["type": kind.rawValue, "chainId": cipher.chainID,
                                      "deviceId": deviceID, "deviceName": deviceName, "deviceType": "Mobile (iOS)",
                                      "timestamp": now.timeIntervalSince1970 * 1000, "sequence": sequence,
                                      "payload": payload]
        let content = try cipher.encryptMessage(JSONSerialization.data(withJSONObject: message))
        return try SyncChunks.split(content).enumerated().map { index, part in
            let tags = kind == .update || kind == .response
                ? [["d", "pksync-v4-\(cipher.chainID)-\(deviceID)-\(kind.rawValue)-\(index)"], ["h", cipher.chainID]]
                : [["d", "pksync-v4-\(cipher.chainID)"]]
            return try cipher.sign(content: part, tags: tags, createdAt: Int64(now.timeIntervalSince1970))
        }
    }

    private func dictionary(_ data: Data) throws -> [String: Any] {
        guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SyncError.invalidMessage
        }
        return result
    }

    private func records(_ object: [String: Any], _ key: String) throws -> [[String: Any]] {
        guard let value = object[key] else { return [] }
        guard let records = value as? [[String: Any]] else { throw SyncError.invalidMessage }
        return records
    }

    private func string(_ object: Any) throws -> String {
        String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes]), as: UTF8.self)
    }
}
