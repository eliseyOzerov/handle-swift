import HandleSecurity
import XCTest

final class KeychainTestHandleTests: XCTestCase {
  func testKeychainTestStoresFindsAndDeletesPasswordValues() throws {
    let keychain = SecurityHandle.Keychain.Test()
    let attributes = SecurityHandle.Keychain.Password.Attributes.service(
      "wave-api",
      label: "accessToken"
    )

    XCTAssertNil(try keychain.find(attributes))

    try keychain.save("access-token", for: attributes)
    XCTAssertEqual(try keychain.find(attributes), "access-token")

    try keychain.delete(attributes)
    XCTAssertNil(try keychain.find(attributes))

    XCTAssertEqual(keychain.saveCallCount, 1)
    XCTAssertEqual(keychain.findCallCount, 3)
    XCTAssertEqual(keychain.deleteCallCount, 1)
  }
}
