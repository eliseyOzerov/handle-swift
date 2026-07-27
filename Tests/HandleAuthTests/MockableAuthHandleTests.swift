import HandleAuth
import Mockable
import XCTest

final class MockableAuthHandleTests: XCTestCase {
  @MainActor
  func testMockableCanMockAppleProtocol() async throws {
    let apple = AuthHandle.Apple.MockService()
    let result = AuthHandle.Apple.SignInResult(
      identityToken: "identity-token",
      userID: "user-id",
      nonce: "nonce"
    )

    given(apple)
      .signIn(options: .any)
      .willReturn(result)

    let received = try await apple.signIn(options: .init())

    XCTAssertEqual(received, result)
    verify(apple)
      .signIn(options: .any)
      .called(.once)
  }

  @MainActor
  func testMockableCanMockLocalProtocol() async throws {
    let local = AuthHandle.Local.MockService()
    let result = AuthHandle.Local.Result(policy: .biometrics, biometryType: .faceID)

    given(local)
      .authenticate(reason: .any, policy: .any, options: .any)
      .willReturn(result)

    let received = try await local.authenticate(
      reason: "Unlock",
      policy: .biometrics,
      options: .init()
    )

    XCTAssertEqual(received, result)
    verify(local)
      .authenticate(reason: .value("Unlock"), policy: .value(.biometrics), options: .any)
      .called(.once)
  }
}
