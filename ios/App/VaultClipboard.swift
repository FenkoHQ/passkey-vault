import UIKit

@MainActor
final class VaultClipboard {
    private static let lifetime: TimeInterval = 30
    private var copiedChange: Int?

    func copyCode(_ code: String) {
        let pasteboard = UIPasteboard.general
        pasteboard.setObjects([code as NSString], localOnly: true,
                              expirationDate: Date().addingTimeInterval(Self.lifetime))
        copiedChange = pasteboard.changeCount
    }

    func clear() {
        let pasteboard = UIPasteboard.general
        // Leave anything copied by another app intact.
        if copiedChange == pasteboard.changeCount { pasteboard.items = [] }
        copiedChange = nil
    }
}
