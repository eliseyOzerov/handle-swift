import Foundation
import HandleSecurity
import XCTest

final class KeychainTestHandleTests: XCTestCase {
  private struct Session: Codable, Equatable {
    var accessToken: String
    var refreshToken: String
  }

  func testKeychainStoresFindsAndDeletesStringValues() throws {
    let keychain = SecurityHandle.Keychain.shared
    let attributes = makeAttributes(label: "accessToken")
    try deleteExistingItem(keychain: keychain, attributes: attributes)
    XCTAssertNil(try keychain.findString(attributes))

    try keychain.save("access-token", for: attributes)
    XCTAssertEqual(try keychain.findString(attributes), "access-token")

    try keychain.delete(attributes)
    XCTAssertNil(try keychain.findString(attributes))
  }

  func testKeychainStoresFindsAndDeletesDataValues() throws {
    let keychain = SecurityHandle.Keychain.shared
    let attributes = makeAttributes(label: "sessionData")
    let data = Data([0, 1, 2, 3, 255])
    try deleteExistingItem(keychain: keychain, attributes: attributes)
    XCTAssertNil(try keychain.find(attributes))

    try keychain.save(data, for: attributes)
    XCTAssertEqual(try keychain.find(attributes), data)

    try keychain.delete(attributes)
    XCTAssertNil(try keychain.find(attributes))
  }

  func testKeychainStoresFindsAndDeletesCodableValues() throws {
    let keychain = SecurityHandle.Keychain.shared
    let attributes = makeAttributes(label: "session")
    let session = Session(accessToken: "access-token", refreshToken: "refresh-token")
    try deleteExistingItem(keychain: keychain, attributes: attributes)
    XCTAssertNil(try keychain.find(Session.self, for: attributes))

    try keychain.save(session, for: attributes)
    XCTAssertEqual(try keychain.find(Session.self, for: attributes), session)

    try keychain.delete(attributes)
    XCTAssertNil(try keychain.find(Session.self, for: attributes))
  }

  private func makeAttributes(label: String) -> SecurityHandle.Keychain.Password.Attributes {
    SecurityHandle.Keychain.Password.Attributes.service(
      "handle-security-tests.\(UUID().uuidString)",
      label: label,
      account: "KeychainTestHandleTests"
    )
  }

  private func deleteExistingItem(
    keychain: SecurityHandle.Keychain,
    attributes: SecurityHandle.Keychain.Password.Attributes
  ) throws {
    try keychain.delete(attributes)
  }
}
