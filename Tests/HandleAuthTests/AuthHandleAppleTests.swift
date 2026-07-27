import HandleAuth
import XCTest

final class AuthHandleAppleTests: XCTestCase {
  @MainActor
  func testAppleTestHandleReturnsConfiguredSignInResult() async throws {
    let apple = AuthHandle.Apple.Test()
    let result = AuthHandle.Apple.SignInResult(
      identityToken: "identity-token",
      userID: "user-id",
      nonce: "nonce",
      email: "user@example.com",
      displayName: "Taylor"
    )

    apple.setSignInResult(result)

    let received = try await apple.signIn()

    XCTAssertEqual(received, result)
    XCTAssertEqual(apple.signInCallCount, 1)
    XCTAssertEqual(apple.signInCalls, [AuthHandle.Apple.SignInCall(options: .init())])
  }

  @MainActor
  func testAppleTestHandleCanMatchSignInOptions() async throws {
    let apple = AuthHandle.Apple.Test()
    let emailOnly = AuthHandle.Apple.SignInOptions(scopes: .email)
    let result = AuthHandle.Apple.SignInResult(
      identityToken: "email-token",
      userID: "user-id",
      nonce: "nonce"
    )

    apple.setSignInError(AuthHandle.Apple.TestError.unhandledSignIn)
    apple.setSignInResult(result, for: emailOnly)

    let received = try await apple.signIn(options: emailOnly)

    XCTAssertEqual(received.identityToken, "email-token")
    XCTAssertEqual(apple.signInCalls.map(\.options), [emailOnly])
  }

  @MainActor
  func testAppleTestHandleStoresCredentialState() async throws {
    let apple = AuthHandle.Apple.Test()

    apple.setCredentialState(.authorized, for: "user-id")

    let state = try await apple.credentialState(for: "user-id")

    XCTAssertEqual(state, .authorized)
  }

  func testAppleDefaultOptionsRequestFullNameAndEmail() {
    let options = AuthHandle.Apple.SignInOptions()

    XCTAssertEqual(options.scopes, .standard)
    XCTAssertTrue(options.preservesDisplayName)
  }
}
