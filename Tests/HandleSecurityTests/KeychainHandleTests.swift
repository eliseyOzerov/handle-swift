import Foundation
import HandleSecurity
import XCTest

final class KeychainHandleTests: XCTestCase {
  func testTestKeychainHandleStoresStringsInMemory() throws {
    let keychain = TestKeychainHandle()
    let key = KeychainKey.service("wave-api", "accessToken")

    try keychain.set("token", for: key)

    XCTAssertEqual(try keychain.string(for: key), "token")
    XCTAssertEqual(keychain.setDataCallCount, 1)
    XCTAssertEqual(keychain.dataCallCount, 1)
    XCTAssertEqual(keychain.setDataCalls.first?.key, key)
  }

  func testTestKeychainHandleDeletesStoredValues() throws {
    let key = KeychainKey.service("wave-api", "refreshToken")
    let keychain = TestKeychainHandle(storage: [key: Data("refresh".utf8)])

    try keychain.delete(key)

    XCTAssertNil(try keychain.data(for: key))
    XCTAssertEqual(keychain.deleteCalls, [TestKeychainHandle.DeleteCall(key: key)])
  }

  func testTestKeychainHandleCanStubReads() throws {
    let key = KeychainKey.service("wave-api", "accessToken")
    let keychain = TestKeychainHandle()
    keychain.dataHandler = { requestedKey in
      requestedKey == key ? Data("stubbed".utf8) : nil
    }

    XCTAssertEqual(try keychain.string(for: key), "stubbed")
    XCTAssertEqual(keychain.dataCalls, [TestKeychainHandle.DataCall(key: key)])
  }

  func testStringReadRejectsInvalidUTF8() throws {
    let key = KeychainKey.service("wave-api", "binary")
    let keychain = TestKeychainHandle(storage: [key: Data([0xFF])])

    XCTAssertThrowsError(try keychain.string(for: key)) { error in
      XCTAssertEqual(error as? KeychainHandleError, .invalidStringData)
    }
  }
}
