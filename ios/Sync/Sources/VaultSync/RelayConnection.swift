import Foundation

protocol RelayConnection: Sendable {
    func send(_ text: String) async throws
    func receive() async throws -> String
    func close() async
}

enum RelayLimits {
    static let maxFrameBytes = SyncCipher.maxEventBytes + 2048
    static let connectionTimeout: TimeInterval = 30
}

final class URLRelayConnection: RelayConnection {
    private let session: URLSession
    private let task: URLSessionWebSocketTask

    init(url: URL) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = RelayLimits.connectionTimeout
        session = URLSession(configuration: configuration)
        task = session.webSocketTask(with: url)
        task.maximumMessageSize = RelayLimits.maxFrameBytes
        task.resume()
    }

    func send(_ text: String) async throws {
        guard text.utf8.count <= RelayLimits.maxFrameBytes else { throw SyncError.capacity }
        try await task.send(.string(text))
    }

    func receive() async throws -> String {
        switch try await task.receive() {
        case .string(let text): return text
        case .data(let data):
            guard let text = String(data: data, encoding: .utf8) else { throw SyncError.invalidMessage }
            return text
        @unknown default: throw SyncError.invalidMessage
        }
    }

    func close() async {
        task.cancel(with: .goingAway, reason: nil)
        session.invalidateAndCancel()
    }
}
