import HandleSecurity
import Mockable
import XCTest

final class MockableKeychainTests: XCTestCase {
  func testMockableCanMockKeychainProtocol() throws {
    let keychain = SecurityHandle.Keychain.Mock()
    let attributes = SecurityHandle.Keychain.Password.Attributes.service(
      "wave-api",
      label: "accessToken"
    )

    given(keychain)
      .find(.any, matching: .any)
      .willReturn(Data("token".utf8))

    let token = try keychain.findString(attributes, matching: .init())

    XCTAssertEqual(token, "token")
    verify(keychain)
      .find(.any, matching: .any)
      .called(.once)
  }
}
