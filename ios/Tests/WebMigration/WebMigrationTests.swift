import XCTest
import WebKit
@testable import FenkoVault

@MainActor
final class WebMigrationTests: XCTestCase {
    func testLegacyFileOrigin() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let oldWeb = directory.appendingPathComponent("old-install/web", isDirectory: true)
        try FileManager.default.createDirectory(at: oldWeb, withIntermediateDirectories: true)
        let oldURL = oldWeb.appendingPathComponent("index.html")
        try "<!doctype html><title>Legacy fixture</title>".write(to: oldURL, atomically: true, encoding: .utf8)
        let store = WKWebsiteDataStore.default()
        await store.removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(), modifiedSince: .distantPast)
        let writer = FixtureWriter()
        let view = try await writer.load(oldURL)
        _ = try await view.evaluateJavaScript("""
            localStorage.setItem('totp_entries', JSON.stringify([{
              id: 'legacy-otp', issuer: 'Example', account: 'alice',
              secretB64: 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=', algorithm: 'SHA1',
              digits: 6, period: 30, type: 'totp', createdAt: 1
            }])); true;
            """)
        let archive = VaultArchive(directory: directory.appendingPathComponent("encrypted"))
        try archive.unlock(key: Data(repeating: 43, count: 32))
        let vault = VaultStore(archive: archive)
        try await LegacyWebMigration(vault: vault).run()
        XCTAssertEqual(try vault.loadTOTP().map(\.id), ["legacy-otp"])
        XCTAssertFalse(try vault.needsWebMigration())
        let remaining = try await LegacyWebReader().read(oldURL)
        XCTAssertTrue(remaining.values.isEmpty, "Migration left plaintext web storage")
        try await LegacyWebMigration(vault: vault).run()
        XCTAssertEqual(try vault.loadTOTP().count, 1)
    }
}

@MainActor
private final class FixtureWriter: NSObject, WKNavigationDelegate {
    private var pending: CheckedContinuation<WKWebView, Error>?
    private var view: WKWebView?

    func load(_ url: URL) async throws -> WKWebView {
        try await withCheckedThrowingContinuation { pending in
            self.pending = pending
            let view = WKWebView()
            self.view = view
            view.navigationDelegate = self
            view.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        pending?.resume(returning: webView)
        pending = nil
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        pending?.resume(throwing: error)
        pending = nil
    }
}
