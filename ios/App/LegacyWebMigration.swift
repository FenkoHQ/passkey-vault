import Foundation
import WebKit

@MainActor
final class LegacyWebMigration {
    private let vault: VaultStore

    init(vault: VaultStore = .shared) { self.vault = vault }

    func run() async throws {
        guard try vault.needsWebMigration() else { return }
        guard let url = Bundle.main.url(forResource: "index", withExtension: "html", subdirectory: "web") else {
            throw VaultError.unavailable
        }
        let reader = LegacyWebReader()
        let snapshot = try await reader.read(url)
        try Task.checkCancellation()
        try vault.importLegacyWeb(snapshot)
        await WKWebsiteDataStore.default().removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(),
                                                      modifiedSince: .distantPast)
        try vault.finishWebMigration()
    }
}

@MainActor
final class LegacyWebReader: NSObject, WKNavigationDelegate {
    private var webView: WKWebView?
    private var continuation: CheckedContinuation<LegacyWebSnapshot, Error>?
    private var timeout: Task<Void, Never>?
    private var expectedURL: URL?
    private static let timeoutSeconds: UInt64 = 15

    func read(_ url: URL) async throws -> LegacyWebSnapshot {
        try Task.checkCancellation()
        guard continuation == nil else { throw VaultError.unavailable }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                self.continuation = continuation
                expectedURL = url
                let configuration = WKWebViewConfiguration()
                configuration.websiteDataStore = .default()
                let view = WKWebView(frame: .zero, configuration: configuration)
                webView = view
                view.navigationDelegate = self
                view.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
                timeout = Task { [weak self] in
                    do { try await Task.sleep(nanoseconds: Self.timeoutSeconds * 1_000_000_000) }
                    catch { return }
                    self?.finish(.failure(VaultError.unavailable))
                }
            }
        } onCancel: {
            Task { @MainActor [weak self] in self?.finish(.failure(CancellationError())) }
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard let encoded = try? JSONEncoder().encode(LegacyWebSnapshot.keys),
              let keys = String(data: encoded, encoding: .utf8) else {
            finish(.failure(VaultError.invalidData))
            return
        }
        let script = "Object.fromEntries(\(keys).map(k => [k, localStorage.getItem(k)]).filter(e => e[1] !== null))"
        webView.evaluateJavaScript(script) { [weak self] result, error in
            if let error { self?.finish(.failure(error)); return }
            guard let values = result as? [String: String] else {
                self?.finish(.failure(VaultError.invalidData))
                return
            }
            do { self?.finish(.success(try LegacyWebSnapshot(values))) }
            catch { self?.finish(.failure(error)) }
        }
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        decisionHandler(action.request.url == expectedURL ? .allow : .cancel)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        finish(.failure(error))
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<LegacyWebSnapshot, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        timeout?.cancel()
        timeout = nil
        webView?.navigationDelegate = nil
        webView?.stopLoading()
        webView = nil
        continuation.resume(with: result)
    }
}
