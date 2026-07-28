import HandleAuth
import Mockable
import XCTest

final class MockableAuthHandleTests: XCTestCase {
  @MainActor
  func testMockableCanMockAppleProtocol() async throws {
    let apple = AuthHandle.Apple.Mock()
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
  func testMockableCanSpyOnAppleDefaultSignIn() async throws {
    let apple = AuthHandle.Apple.Mock()
    let result = AuthHandle.Apple.SignInResult(
      identityToken: "default-token",
      userID: "user-id",
      nonce: "nonce"
    )

    given(apple)
      .signIn(options: .value(.init()))
      .willReturn(result)

    let received = try await apple.signIn()

    XCTAssertEqual(received, result)
    verify(apple)
      .signIn(options: .value(.init()))
      .called(.once)
  }

  @MainActor
  func testMockableCanMockAppleCredentialState() async throws {
    let apple = AuthHandle.Apple.Mock()

    given(apple)
      .credentialState(for: .value("user-id"))
      .willReturn(.authorized)

    let state = try await apple.credentialState(for: "user-id")

    XCTAssertEqual(state, .authorized)
    verify(apple)
      .credentialState(for: .value("user-id"))
      .called(.once)
  }

  @MainActor
  func testMockableCanMockLocalProtocol() async throws {
    let local = AuthHandle.Local.Mock()
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
