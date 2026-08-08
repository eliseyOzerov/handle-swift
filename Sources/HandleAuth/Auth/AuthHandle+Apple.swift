import AuthenticationServices
import CryptoKit
import Foundation
import HandleSecurity
import Mockable
import Security

extension AuthHandle {
  /// Async Sign in with Apple handle.
  public final class Apple: @unchecked Sendable {
    public static let shared = Apple()

    private let displayNameStore: DisplayNameStore?
    private var activeSession: AppleAuthorizationSession?

    public init(displayNameStore: DisplayNameStore? = .keychain()) {
      self.displayNameStore = displayNameStore
    }

    /// Starts a Sign in with Apple request and returns the resulting identity token.
    @MainActor
    public func signIn(options: SignInOptions = SignInOptions()) async throws -> SignInResult {
      guard activeSession == nil else {
        throw Error.signInAlreadyInProgress
      }

      let session = AppleAuthorizationSession(options: options, displayNameStore: displayNameStore)
      activeSession = session
      defer { activeSession = nil }
      return try await session.signIn()
    }

    /// Returns Apple's current credential state for a user identifier.
    @MainActor
    public func credentialState(for userID: String) async throws -> CredentialState {
      try await withCheckedThrowingContinuation { continuation in
        ASAuthorizationAppleIDProvider().getCredentialState(forUserID: userID) { state, error in
          if let error {
            continuation.resume(throwing: error)
          } else {
            continuation.resume(returning: CredentialState(state))
          }
        }
      }
    }
  }
}

extension AuthHandle.Apple {
  @Mockable
  public protocol Interface: Sendable {
    @MainActor
    func signIn(options: SignInOptions) async throws -> SignInResult

    @MainActor
    func credentialState(for userID: String) async throws -> CredentialState
  }

  #if MOCKING
  public typealias Mock = MockInterface
  #endif

  public enum Error: Swift.Error, Equatable {
    case invalidCredential
    case signInAlreadyInProgress
  }


  public struct Scopes: OptionSet, Sendable {
    public let rawValue: Int

    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    public static let fullName = Scopes(rawValue: 1 << 0)
    public static let email = Scopes(rawValue: 1 << 1)
    public static let standard: Scopes = [.fullName, .email]

    var authorizationScopes: [ASAuthorization.Scope] {
      var scopes: [ASAuthorization.Scope] = []
      if contains(.fullName) {
        scopes.append(.fullName)
      }
      if contains(.email) {
        scopes.append(.email)
      }
      return scopes
    }
  }

  public struct SignInOptions: Sendable, Equatable {
    public var scopes: Scopes
    public var preservesDisplayName: Bool

    public init(scopes: Scopes = .standard, preservesDisplayName: Bool = true) {
      self.scopes = scopes
      self.preservesDisplayName = preservesDisplayName
    }
  }

  public struct SignInResult: Sendable, Equatable {
    public var identityToken: String
    public var authorizationCode: String?
    public var userID: String
    public var nonce: String
    public var email: String?
    public var displayName: String?
    public var realUserStatus: RealUserStatus

    public init(
      identityToken: String,
      authorizationCode: String? = nil,
      userID: String,
      nonce: String,
      email: String? = nil,
      displayName: String? = nil,
      realUserStatus: RealUserStatus = .unknown
    ) {
      self.identityToken = identityToken
      self.authorizationCode = authorizationCode
      self.userID = userID
      self.nonce = nonce
      self.email = email
      self.displayName = displayName
      self.realUserStatus = realUserStatus
    }
  }

  public enum RealUserStatus: Sendable, Equatable {
    case unsupported
    case unknown
    case likelyReal

    init(_ status: ASUserDetectionStatus) {
      switch status {
      case .unsupported: self = .unsupported
      case .unknown: self = .unknown
      case .likelyReal: self = .likelyReal
      @unknown default: self = .unknown
      }
    }
  }

  public enum CredentialState: Sendable, Equatable {
    case authorized
    case revoked
    case notFound
    case transferred
    case unknown

    init(_ state: ASAuthorizationAppleIDProvider.CredentialState) {
      switch state {
      case .authorized: self = .authorized
      case .revoked: self = .revoked
      case .notFound: self = .notFound
      case .transferred: self = .transferred
      @unknown default: self = .unknown
      }
    }
  }

  public struct DisplayNameStore: Sendable {
    private let loadValue: @Sendable (String) -> String?
    private let saveValue: @Sendable (String, String) -> Void

    public init(
      load: @escaping @Sendable (String) -> String?,
      save: @escaping @Sendable (String, String) -> Void
    ) {
      loadValue = load
      saveValue = save
    }

    public func load(userID: String) -> String? {
      loadValue(userID)
    }

    public func save(_ displayName: String, for userID: String) {
      saveValue(userID, displayName)
    }

    public static func keychain(
      _ keychain: SecurityHandle.Keychain = .shared,
      service: String = "handle-auth-apple"
    ) -> DisplayNameStore {
      DisplayNameStore(
        load: { userID in
          try? keychain.findString(attributes(service: service, userID: userID))
        },
        save: { userID, displayName in
          try? keychain.save(displayName, for: attributes(service: service, userID: userID))
        }
      )
    }

    private static func attributes(
      service: String,
      userID: String
    ) -> SecurityHandle.Keychain.Password.Attributes {
      SecurityHandle.Keychain.Password.Attributes.service(
        service,
        label: "displayName",
        account: userID
      )
    }
  }

}

extension AuthHandle.Apple: AuthHandle.Apple.Interface {}

public extension AuthHandle.Apple.Interface {
  @MainActor
  func signIn() async throws -> AuthHandle.Apple.SignInResult {
    try await signIn(options: AuthHandle.Apple.SignInOptions())
  }
}

@MainActor
private final class AppleAuthorizationSession: NSObject, ASAuthorizationControllerDelegate {
  private let options: AuthHandle.Apple.SignInOptions
  private let displayNameStore: AuthHandle.Apple.DisplayNameStore?
  private let nonce: String
  private var controller: ASAuthorizationController?
  private var continuation: CheckedContinuation<AuthHandle.Apple.SignInResult, Swift.Error>?

  init(
    options: AuthHandle.Apple.SignInOptions,
    displayNameStore: AuthHandle.Apple.DisplayNameStore?
  ) {
    self.options = options
    self.displayNameStore = displayNameStore
    nonce = Self.randomNonceString()
  }

  func signIn() async throws -> AuthHandle.Apple.SignInResult {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        self.continuation = continuation
        startSignIn()
      }
    } onCancel: {
      Task { @MainActor in
        self.cancel()
      }
    }
  }

  func cancel() {
    controller?.cancel()
    finish(.failure(CancellationError()))
  }

  private func startSignIn() {
    let request = ASAuthorizationAppleIDProvider().createRequest()
    request.requestedScopes = options.scopes.authorizationScopes
    request.nonce = Self.sha256(nonce)

    let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = self
    self.controller = controller
    controller.performRequests()
  }

  nonisolated func authorizationController(
    controller: ASAuthorizationController,
    didCompleteWithAuthorization authorization: ASAuthorization
  ) {
    Task { @MainActor in
      guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
            let identityToken = credential.identityToken,
            let tokenString = String(data: identityToken, encoding: .utf8) else {
        finish(.failure(AuthHandle.Apple.Error.invalidCredential))
        return
      }

      let code = credential.authorizationCode.flatMap { String(data: $0, encoding: .utf8) }
      let displayName = displayName(from: credential)

      finish(.success(AuthHandle.Apple.SignInResult(
        identityToken: tokenString,
        authorizationCode: code,
        userID: credential.user,
        nonce: nonce,
        email: credential.email,
        displayName: displayName,
        realUserStatus: AuthHandle.Apple.RealUserStatus(credential.realUserStatus)
      )))
    }
  }

  nonisolated func authorizationController(
    controller: ASAuthorizationController,
    didCompleteWithError error: any Swift.Error
  ) {
    Task { @MainActor in
      finish(.failure(error))
    }
  }

  private func finish(_ result: Result<AuthHandle.Apple.SignInResult, Swift.Error>) {
    guard let continuation else { return }
    cleanup()

    switch result {
    case .success(let value):
      continuation.resume(returning: value)
    case .failure(let error):
      continuation.resume(throwing: error)
    }
  }

  private func cleanup() {
    controller = nil
    continuation = nil
  }

  private func displayName(from credential: ASAuthorizationAppleIDCredential) -> String? {
    let name = Self.displayName(from: credential.fullName)

    if let name, options.preservesDisplayName {
      displayNameStore?.save(name, for: credential.user)
      return name
    }

    guard options.preservesDisplayName else {
      return name
    }

    return displayNameStore?.load(userID: credential.user)
  }

  private static func displayName(from components: PersonNameComponents?) -> String? {
    guard let components else { return nil }

    let name = PersonNameComponentsFormatter.localizedString(from: components, style: .default)
      .trimmingCharacters(in: .whitespacesAndNewlines)

    return name.isEmpty ? nil : name
  }

  private static func randomNonceString(length: Int = 32) -> String {
    var randomBytes = [UInt8](repeating: 0, count: length)
    _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
    let charset = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._")
    return String(randomBytes.map { charset[Int($0) % charset.count] })
  }

  private static func sha256(_ input: String) -> String {
    let data = Data(input.utf8)
    let hash = SHA256.hash(data: data)
    return hash.compactMap { String(format: "%02x", $0) }.joined()
  }
}
