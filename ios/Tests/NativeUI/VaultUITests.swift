import XCTest
import UIKit

final class VaultUITests: XCTestCase {
    func testOTPSetupAndDeletion() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.buttons["Unlock vault"].waitForExistence(timeout: 10))
        app.buttons["Unlock vault"].tap()
        XCTAssertTrue(app.buttons["Add 2FA code"].waitForExistence(timeout: 5))
        app.buttons["Add 2FA code"].tap()
        let link = app.secureTextFields["otpauth:// link"]
        XCTAssertTrue(link.waitForExistence(timeout: 5))
        link.tap()
        link.typeText("otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example")
        app.buttons["Read setup link"].tap()
        XCTAssertEqual(app.textFields["Issuer or service"].value as? String, "Example")
        XCTAssertEqual(app.textFields["Account"].value as? String, "alice")
        app.buttons["Save"].tap()
        let entry = app.cells.containing(.staticText, identifier: "Example").firstMatch
        XCTAssertTrue(entry.waitForExistence(timeout: 5))
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "Native vault with authenticator"
        screenshot.lifetime = .keepAlways
        add(screenshot)
        entry.swipeLeft()
        app.buttons["Delete"].tap()
        XCTAssertTrue(app.buttons["Delete Example"].waitForExistence(timeout: 5))
        if UIDevice.current.userInterfaceIdiom == .pad {
            // iPad confirmation popovers dismiss when tapped outside.
            app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.9)).tap()
        } else {
            app.buttons["Cancel"].tap()
        }
        XCTAssertFalse(app.buttons["Delete Example"].exists)
        XCTAssertTrue(entry.exists)
        entry.swipeLeft()
        app.buttons["Delete"].tap()
        app.buttons["Delete Example"].tap()
        XCTAssertTrue(app.staticTexts["Your vault is empty"].waitForExistence(timeout: 5))
        app.buttons["Lock"].tap()
        XCTAssertTrue(app.buttons["Unlock vault"].waitForExistence(timeout: 5))
    }
}
