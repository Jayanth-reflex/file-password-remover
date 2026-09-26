import XCTest

/// The app, driven the way a person drives it: through the system document
/// picker, the keyboard and the buttons, on a simulator.
///
/// The fixtures are put into the app's Documents folder before these run, by
/// `scripts/run_ios_ui_tests.sh`. That folder is exposed to the picker because
/// the app sets `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace`,
/// so choosing a file here goes through exactly the screen a user sees.
final class JourneyUITests: XCTestCase {
    private let password = "correct horse battery staple"
    private var app: XCUIApplication!

    override func setUp() {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launch()
    }

    // MARK: - Journeys

    func testRemovingProtectionFromAPDF() {
        choose("locked")
        XCTAssertTrue(app.staticTexts["user-password"].waitForExistence(timeout: 10))

        type(password, into: app.secureTextFields["password-field"])
        tap(app.buttons["remove-button"])

        XCTAssertTrue(success.waitForExistence(timeout: 30))
        XCTAssertTrue(success.label.contains("Protection removed"))
        // The hallmark row: the evidence from re-reading the written file. It is
        // one accessibility element, read by VoiceOver as a single sentence.
        let hallmark = app.descendants(matching: .any).matching(
            NSPredicate(format: "label BEGINSWITH %@ AND label CONTAINS[c] %@",
                        "Verified.", "encrypted false")
        ).firstMatch
        XCTAssertTrue(hallmark.waitForExistence(timeout: 5), "the hallmark does not say ENCRYPTED false")
    }

    func testRemovingProtectionFromAZip() {
        choose("aes.zip")
        type(password, into: app.secureTextFields["password-field"])
        tap(app.buttons["remove-button"])
        XCTAssertTrue(success.waitForExistence(timeout: 30))
    }

    func testAWrongPasswordIsReportedAndTheRightOneThenWorks() {
        choose("locked")
        type("not the password", into: app.secureTextFields["password-field"])
        tap(app.buttons["remove-button"])
        XCTAssertTrue(failure.waitForExistence(timeout: 30))
        XCTAssertTrue(failure.label.lowercased().contains("password"))

        tap(app.buttons["start-over"])
        choose("locked")
        type(password, into: app.secureTextFields["password-field"])
        tap(app.buttons["remove-button"])
        XCTAssertTrue(success.waitForExistence(timeout: 30))
    }

    func testProtectingWithAGeneratedPasswordShowsItOnce() {
        choose("plain")
        tap(app.buttons["protect-button"])

        let shown = app.staticTexts["generated-password"]
        XCTAssertTrue(shown.waitForExistence(timeout: 30))
        // VoiceOver reads it one character at a time, so the label is spaced out.
        let value = shown.label
            .replacingOccurrences(of: "Generated password: ", with: "")
            .replacingOccurrences(of: " ", with: "")
        XCTAssertNotNil(
            value.range(of: #"^[a-z0-9]{4}(-[a-z0-9]{4}){4}$"#, options: .regularExpression),
            "not a generated password: \(value)"
        )
    }

    /// Behind a mask, one wrong key would lock the file with a password nobody
    /// knows. The button stays disabled until both fields agree.
    func testAChosenPasswordMustBeTypedTwice() {
        choose("plain")
        app.buttons["Use my own"].tap()

        type("typed carefully", into: app.secureTextFields["new-password-field"])
        type("typed carefuly", into: app.secureTextFields["confirm-password-field"])
        XCTAssertTrue(app.staticTexts["password-mismatch"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["protect-button"].isEnabled, "protect is enabled on a mismatch")

        let confirm = app.secureTextFields["confirm-password-field"]
        clear(confirm)
        type("typed carefully", into: confirm)
        XCTAssertTrue(app.buttons["protect-button"].isEnabled)
        tap(app.buttons["protect-button"])
        XCTAssertTrue(success.waitForExistence(timeout: 30))
        XCTAssertTrue(success.label.contains("Protected"))
        // A password the user chose is theirs; it is never displayed back.
        XCTAssertFalse(app.staticTexts["generated-password"].exists)
    }

    func testTheVersionIsShown() {
        let colophon = app.staticTexts.containing(
            NSPredicate(format: "label BEGINSWITH[c] %@", "Version ")
        ).firstMatch
        XCTAssertTrue(colophon.waitForExistence(timeout: 5))
    }

    // MARK: - Helpers

    private var success: XCUIElement { app.descendants(matching: .any)["success"] }
    private var failure: XCUIElement { app.descendants(matching: .any)["error"] }

    /// Pick a file from the app's own folder in the system document picker.
    ///
    /// The picker remembers where it was last; on a fresh simulator it opens
    /// on Recents or the Browse root instead, so fall back to navigating there.
    private func choose(_ name: String) {
        tap(app.buttons["choose-file"])
        // The picker's cells are what select a file; the name label inside a
        // cell does not respond to a tap. A cell is identified as
        // "<name>, <type>", e.g. "locked, pdf" or "aes.zip, zip".
        let file = app.cells
            .matching(NSPredicate(format: "identifier BEGINSWITH %@", "\(name), "))
            .firstMatch
        if !file.waitForExistence(timeout: 5) {
            let browse = app.buttons["Browse"]
            if browse.waitForExistence(timeout: 5) { browse.tap() }
            for location in ["On My iPhone", "On My iPad"] where app.staticTexts[location].exists {
                app.staticTexts[location].tap()
                break
            }
            for folder in ["Password Remover", "File Password Remover", "FilePasswordRemover"]
            where app.staticTexts[folder].waitForExistence(timeout: 3) {
                app.staticTexts[folder].tap()
                break
            }
        }
        XCTAssertTrue(file.waitForExistence(timeout: 10), "\(name) is not in the picker")
        file.tap()
        XCTAssertTrue(app.buttons["start-over"].waitForExistence(timeout: 15), "\(name) did not load")
    }

    private func type(_ text: String, into field: XCUIElement) {
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        field.tap()
        field.typeText(text)
        dismissKeyboard()
    }

    private func clear(_ field: XCUIElement) {
        field.tap()
        let count = (field.value as? String)?.count ?? 32
        field.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: max(count, 32)))
    }

    private func tap(_ element: XCUIElement) {
        XCTAssertTrue(element.waitForExistence(timeout: 10))
        if !element.isHittable { app.swipeUp() }
        element.tap()
    }

    private func dismissKeyboard() {
        let returnKey = app.keyboards.buttons["return"]
        if returnKey.exists { returnKey.tap() }
    }
}
