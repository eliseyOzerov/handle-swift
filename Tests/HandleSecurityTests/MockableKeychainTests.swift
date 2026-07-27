import HandleSecurity
import Mockable
import XCTest

final class MockableKeychainTests: XCTestCase {
  func testMockableCanMockKeychainProtocol() throws {
    let keychain = SecurityHandle.Keychain.MockService()
    let attributes = SecurityHandle.Keychain.Password.Attributes.service(
      "wave-api",
      label: "accessToken"
    )

    given(keychain)
      .find(.any, matching: .any)
      .willReturn("token")

    let token = try keychain.find(attributes, matching: .init())

    XCTAssertEqual(token, "token")
    verify(keychain)
      .find(.any, matching: .any)
      .called(.once)
  }
}
