import Foundation

public struct SyncDelivery: Sendable {
    public enum State: Sendable {
        case pending
        case complete
        case exhausted
    }

    private static let maxAttempts = 5
    private static let initialDelay: TimeInterval = 10
    private static let maxDelay: TimeInterval = 120
    private let frames: [RelayEvent]
    private let ids: Set<String>
    private var accepted: Set<String> = []
    private var attempts = 0
    private var nextAttempt = Date.distantPast

    public init(frames: [RelayEvent]) throws {
        let ids = Set(frames.map(\.id))
        guard !frames.isEmpty, ids.count == frames.count else { throw SyncError.invalidEvent }
        self.frames = frames
        self.ids = ids
    }

    public func state(at now: Date = Date()) -> State {
        if accepted == ids { return .complete }
        if attempts >= Self.maxAttempts && now >= nextAttempt { return .exhausted }
        return .pending
    }

    public mutating func acknowledge(_ id: String) -> Bool {
        guard ids.contains(id) else { return false }
        accepted.insert(id)
        return true
    }

    public mutating func take(at now: Date = Date()) -> [RelayEvent] {
        guard state(at: now) == .pending, now >= nextAttempt else { return [] }
        nextAttempt = now.addingTimeInterval(min(Self.initialDelay * pow(2, Double(attempts)), Self.maxDelay))
        attempts += 1
        // Retry identical signed events so delayed acknowledgements still apply.
        return frames.filter { !accepted.contains($0.id) }
    }

    public mutating func retry() {
        attempts = 0
        nextAttempt = .distantPast
    }
}
