import SwiftUI
import WebKit

/// Hosts the shared web app (the same app.ts the Android app and browser
/// extensions run) in a WKWebView. The sync engine — Nostr relays, BIP39 key
/// derivation, AES-GCM, secp256k1 Schnorr — runs entirely in JS, so iOS syncs
/// with every other platform using identical code. Native only bridges vault
/// persistence (so the credential provider can read it), clipboard, and toast.
struct WebVaultView: UIViewRepresentable {
    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> WKWebView {
        let controller = WKUserContentController()
        controller.add(context.coordinator, name: "bridge")
        controller.addUserScript(WKUserScript(
            source: Self.bridgeShim(snapshot: VaultStore.shared.snapshotJSON()),
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true))

        let config = WKWebViewConfiguration()
        config.userContentController = controller
        config.websiteDataStore = .default()   // persistent localStorage across launches

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        // Only allow Web Inspector attachment in debug builds. In a release
        // build this would let a paired Mac read the decrypted vault (including
        // private keys) out of the page's JS context.
        #if DEBUG
        webView.isInspectable = true
        #endif
        if let url = Bundle.main.url(forResource: "index", withExtension: "html", subdirectory: "web") {
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    /// Defines `window.AndroidBridge` (the contract app.ts expects) backed by a
    /// WKScriptMessageHandler. Synchronous calls (loadVaultSnapshot, canUseBiometrics)
    /// are served from values injected here; void calls post to native.
    static func bridgeShim(snapshot: String) -> String {
        let literal = (try? String(data: JSONEncoder().encode(snapshot), encoding: .utf8) ?? "\"\"") ?? "\"\""
        return """
        (function () {
          window.__fenkoSnapshot = \(literal);
          function post(msg) { try { window.webkit.messageHandlers.bridge.postMessage(msg); } catch (e) {} }
          window.AndroidBridge = {
            copyText: function (v) { post({ action: 'copy', value: v }); },
            toast: function (v) { post({ action: 'toast', value: v }); },
            loadVaultSnapshot: function () { return window.__fenkoSnapshot || ''; },
            saveVaultSnapshot: function (p, t, s, d, r) {
              post({ action: 'save', passkeys: p, totp: t, syncConfig: s, syncDevices: d, customRelays: r });
            },
            canUseBiometrics: function () { return false; },
            requestBiometricUnlock: function () {}
          };
        })();
        """
    }

    final class Coordinator: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
        /// Keep the vault itself in the WebView and push everything else (the
        /// feedback form, any future external link) out to the system browser.
        /// Without this, tapping a link would replace the vault UI with a remote
        /// page inside the app, with no way back and no address bar.
        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = navigationAction.request.url else {
                decisionHandler(.allow)
                return
            }
            if url.isFileURL || url.scheme == "about" {
                decisionHandler(.allow)
                return
            }
            decisionHandler(.cancel)
            UIApplication.shared.open(url)
        }

        func userContentController(_ controller: WKUserContentController,
                                   didReceive message: WKScriptMessage) {
            guard message.name == "bridge",
                  let body = message.body as? [String: Any],
                  let action = body["action"] as? String else { return }
            switch action {
            case "save":
                VaultStore.shared.saveSnapshotFromWeb(
                    passkeys: body["passkeys"] as? String,
                    totp: body["totp"] as? String,
                    syncConfig: body["syncConfig"] as? String,
                    syncDevices: body["syncDevices"] as? String,
                    customRelays: body["customRelays"] as? String)
            case "copy":
                if let v = body["value"] as? String { UIPasteboard.general.string = v }
            default:
                break
            }
        }
    }
}
