import Foundation
import HandleSecurity
import XCTest

final class SecurityHandleTests: XCTestCase {
  func testForgeStylePasswordAttributesRemainAvailable() {
    let attributes = SecurityHandle.Keychain.Password.Attributes.service(
      "wave-api",
      label: "accessToken",
      account: "user"
    )

    XCTAssertEqual(attributes.kind, .generic)
    XCTAssertEqual(attributes.service, "wave-api")
    XCTAssertEqual(attributes.account, "user")
    XCTAssertEqual(attributes.generic, Data("accessToken".utf8))
  }

  func testSecurityHandleErrorMapsStatusValues() {
    XCTAssertEqual(SecurityHandle.Error.fromValue(errSecDuplicateItem), .duplicateItem)
    XCTAssertEqual(SecurityHandle.Error.fromValue(errSecItemNotFound), .itemNotFound)
    XCTAssertEqual(SecurityHandle.Error.duplicateItem.statusValue, errSecDuplicateItem)
  }

  func testSecurityHandleNamespaceExposesKeychainItemTypes() {
    _ = SecurityHandle.Keychain.Attributes()
    _ = SecurityHandle.Keychain.Match()
    _ = SecurityHandle.Keychain.Key.Attributes(applicationTag: Data("tag".utf8))
    _ = SecurityHandle.Keychain.Certificate.Attributes()
    _ = SecurityHandle.Keychain.Identity.Attributes()
  }

  func testKeychainPasswordConvenienceUsesNamespaceOnly() {
    let attributes = SecurityHandle.Keychain.Password.Attributes.key("accessToken")

    XCTAssertEqual(attributes.kind, .generic)
    XCTAssertEqual(attributes.generic, Data("accessToken".utf8))
  }
}
