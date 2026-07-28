import HandleAuth
import XCTest

final class AuthHandleAppleTests: XCTestCase {
  func testAppleDefaultOptionsRequestFullNameAndEmail() {
    let options = AuthHandle.Apple.SignInOptions()

    XCTAssertEqual(options.scopes, .standard)
    XCTAssertTrue(options.preservesDisplayName)
  }
}
