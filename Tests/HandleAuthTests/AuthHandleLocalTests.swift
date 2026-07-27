import HandleAuth
import XCTest

final class AuthHandleLocalTests: XCTestCase {
  @MainActor
  func testLocalTestHandleReturnsConfiguredAuthenticationResult() async throws {
    let local = AuthHandle.Local.Test()
    let result = AuthHandle.Local.Result(
      policy: .deviceOwner,
      biometryType: .faceID,
      domainState: Data("domain-state".utf8)
    )
    let options = AuthHandle.Local.PromptOptions(
      fallbackTitle: "Use Passcode",
      cancelTitle: "Cancel"
    )

    local.setAuthenticationResult(result)

    let received = try await local.authenticate(
      reason: "Unlock",
      policy: .deviceOwner,
      options: options
    )

    XCTAssertEqual(received, result)
    XCTAssertEqual(local.authenticationCallCount, 1)
    XCTAssertEqual(local.authenticationCalls, [
      AuthHandle.Local.AuthenticationCall(
        reason: "Unlock",
        policy: .deviceOwner,
        options: options
      )
    ])
  }

  @MainActor
  func testLocalTestHandleCanMatchAuthenticationPolicy() async throws {
    let local = AuthHandle.Local.Test()
    let result = AuthHandle.Local.Result(policy: .biometrics, biometryType: .touchID)

    local.setAuthenticationError(AuthHandle.Local.TestError.unhandledAuthentication)
    local.setAuthenticationResult(result, for: .biometrics)

    let received = try await local.authenticate(reason: "Unlock", policy: .biometrics)

    XCTAssertEqual(received, result)
    XCTAssertEqual(local.authenticationCalls.map(\.policy), [.biometrics])
  }

  @MainActor
  func testLocalTestHandleStoresAvailabilityAndBiometryType() {
    let local = AuthHandle.Local.Test()
    let availability = AuthHandle.Local.Availability(
      isAvailable: true,
      policy: .biometrics,
      biometryType: .opticID
    )

    local.setBiometryType(.opticID)
    local.setAvailability(availability, for: .biometrics)

    XCTAssertEqual(local.biometryType, .opticID)
    XCTAssertEqual(local.canAuthenticate(policy: .biometrics), availability)
  }

  func testLocalDefaultPromptOptionsAllowInteraction() {
    let options = AuthHandle.Local.PromptOptions()

    XCTAssertTrue(options.allowsInteraction)
    XCTAssertNil(options.fallbackTitle)
    XCTAssertNil(options.cancelTitle)
  }
}
