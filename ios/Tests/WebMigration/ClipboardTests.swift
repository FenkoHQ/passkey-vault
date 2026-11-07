import UIKit
import XCTest
@testable import FenkoVault

@MainActor
final class ClipboardTests: XCTestCase {
    func testClearsOnlyOwnCopy() {
        let clipboard = VaultClipboard()
        clipboard.copyCode("123456")
        XCTAssertEqual(UIPasteboard.general.string, "123456")
        clipboard.clear()
        XCTAssertFalse(UIPasteboard.general.hasStrings)
        clipboard.copyCode("234567")
        UIPasteboard.general.string = "Something copied later"
        clipboard.clear()
        XCTAssertEqual(UIPasteboard.general.string, "Something copied later")
        UIPasteboard.general.items = []
    }

    func testCodeExpires() async throws {
        let clipboard = VaultClipboard()
        clipboard.copyCode("345678")
        XCTAssertEqual(UIPasteboard.general.string, "345678")
        try await Task.sleep(nanoseconds: 32_000_000_000)
        XCTAssertNil(UIPasteboard.general.string, "The system retained an expired code")
    }
}
