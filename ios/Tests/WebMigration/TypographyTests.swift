import UIKit
import XCTest

final class TypographyTests: XCTestCase {
    func testBundledFontIsAvailable() {
        let registered = UIFont.familyNames.filter { $0.contains("Saira") }
            .flatMap { UIFont.fontNames(forFamilyName: $0) }
        XCTAssertNotNil(UIFont(name: "Saira", size: 17),
                        "The UI font name is unavailable. Registered Saira faces: \(registered)")
    }
}
