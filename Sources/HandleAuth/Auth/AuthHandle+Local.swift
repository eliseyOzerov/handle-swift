import Foundation
import LocalAuthentication
import Security

extension AuthHandle {
  /// Async local authentication handle for biometry, passcode, and access controls.
  public class Local: @unchecked Sendable {
    public static let shared = Local()

    public init() {}

    /// Returns the device's current biometry type.
    @MainActor
    open var biometryType: BiometryType {
      let context = LAContext()
      _ = context.canEvaluatePolicy(LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: nil)
      return BiometryType(context.biometryType)
    }

    /// Checks whether local authentication can be evaluated for a policy.
    @MainActor
    open func canAuthenticate(policy: Policy = .deviceOwner) -> Availability {
      let context = LAContext()
      var error: NSError?

      if context.canEvaluatePolicy(policy.localAuthenticationPolicy, error: &error) {
        return Availability(
          isAvailable: true,
          policy: policy,
          biometryType: BiometryType(context.biometryType),
          error: nil
        )
      }

      return Availability(
        isAvailable: false,
        policy: policy,
        biometryType: BiometryType(context.biometryType),
        error: error.map(Error.init)
      )
    }

    /// Prompts the user to authenticate with biometry, passcode, or a companion device depending on policy.
    @MainActor
    open func authenticate(
      reason: String,
      policy: Policy = .deviceOwner,
      options: PromptOptions = PromptOptions()
    ) async throws -> Result {
      let context = LAContext()
      options.apply(to: context)

      let success = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Bool, Swift.Error>) in
        context.evaluatePolicy(policy.localAuthenticationPolicy, localizedReason: reason) { success, error in
          if let error {
            continuation.resume(throwing: Error(error))
          } else {
            continuation.resume(returning: success)
          }
        }
      }

      guard success else {
        throw Error.authenticationFailed
      }

      return Result(
        policy: policy,
        biometryType: BiometryType(context.biometryType),
        domainState: context.evaluatedPolicyDomainState
      )
    }

    /// Prompts the user to authenticate before evaluating a Security.framework access control.
    @MainActor
    open func authenticate(
      accessControl: SecAccessControl,
      operation: AccessControlOperation = .useItem,
      reason: String,
      options: PromptOptions = PromptOptions()
    ) async throws -> Result {
      let context = LAContext()
      options.apply(to: context)

      let success = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Bool, Swift.Error>) in
        context.evaluateAccessControl(
          accessControl,
          operation: operation.localAuthenticationOperation,
          localizedReason: reason
        ) { success, error in
          if let error {
            continuation.resume(throwing: Error(error))
          } else {
            continuation.resume(returning: success)
          }
        }
      }

      guard success else {
        throw Error.authenticationFailed
      }

      return Result(
        policy: nil,
        biometryType: BiometryType(context.biometryType),
        domainState: context.evaluatedPolicyDomainState
      )
    }
  }
}

extension AuthHandle.Local {
  public enum Policy: Sendable, Equatable {
    case deviceOwner
    case biometrics

    var localAuthenticationPolicy: LAPolicy {
      switch self {
      case .deviceOwner:
        LAPolicy.deviceOwnerAuthentication
      case .biometrics:
        LAPolicy.deviceOwnerAuthenticationWithBiometrics
      }
    }
  }

  public enum AccessControlOperation: Sendable, Equatable {
    case createItem
    case useItem
    case createKey
    case useKeySign

    var localAuthenticationOperation: LAAccessControlOperation {
      switch self {
      case .createItem:
        LAAccessControlOperation.createItem
      case .useItem:
        LAAccessControlOperation.useItem
      case .createKey:
        LAAccessControlOperation.createKey
      case .useKeySign:
        LAAccessControlOperation.useKeySign
      }
    }
  }

  public enum BiometryType: Sendable, Equatable {
    case none
    case touchID
    case faceID
    case opticID
    case unknown(Int)

    init(_ type: LABiometryType) {
      switch type {
      case .none:
        self = .none
      case .touchID:
        self = .touchID
      case .faceID:
        self = .faceID
      case .opticID:
        self = .opticID
      @unknown default:
        self = .unknown(type.rawValue)
      }
    }
  }

  public struct PromptOptions: Sendable, Equatable {
    public var fallbackTitle: String?
    public var cancelTitle: String?
    public var allowsInteraction: Bool
    public var touchIDAuthenticationAllowableReuseDuration: TimeInterval?

    public init(
      fallbackTitle: String? = nil,
      cancelTitle: String? = nil,
      allowsInteraction: Bool = true,
      touchIDAuthenticationAllowableReuseDuration: TimeInterval? = nil
    ) {
      self.fallbackTitle = fallbackTitle
      self.cancelTitle = cancelTitle
      self.allowsInteraction = allowsInteraction
      self.touchIDAuthenticationAllowableReuseDuration = touchIDAuthenticationAllowableReuseDuration
    }

    func apply(to context: LAContext) {
      context.localizedFallbackTitle = fallbackTitle
      context.localizedCancelTitle = cancelTitle
      context.interactionNotAllowed = !allowsInteraction

      if let touchIDAuthenticationAllowableReuseDuration {
        context.touchIDAuthenticationAllowableReuseDuration = touchIDAuthenticationAllowableReuseDuration
      }
    }
  }

  public struct Availability: Sendable, Equatable {
    public var isAvailable: Bool
    public var policy: Policy
    public var biometryType: BiometryType
    public var error: Error?

    public init(
      isAvailable: Bool,
      policy: Policy,
      biometryType: BiometryType,
      error: Error? = nil
    ) {
      self.isAvailable = isAvailable
      self.policy = policy
      self.biometryType = biometryType
      self.error = error
    }
  }

  public struct Result: Sendable, Equatable {
    public var policy: Policy?
    public var biometryType: BiometryType
    public var domainState: Data?

    public init(policy: Policy?, biometryType: BiometryType, domainState: Data? = nil) {
      self.policy = policy
      self.biometryType = biometryType
      self.domainState = domainState
    }
  }

  public struct AuthenticationCall: Sendable, Equatable {
    public var reason: String
    public var policy: Policy
    public var options: PromptOptions

    public init(reason: String, policy: Policy, options: PromptOptions) {
      self.reason = reason
      self.policy = policy
      self.options = options
    }
  }

  public enum Error: Swift.Error, Sendable, Equatable {
    case authenticationFailed
    case appCancel
    case biometryDisconnected
    case biometryLockout
    case biometryNotAvailable
    case biometryNotEnrolled
    case invalidContext
    case notInteractive
    case passcodeNotSet
    case systemCancel
    case userCancel
    case userFallback
    case localAuthentication(code: Int)

    init(_ error: Swift.Error) {
      guard let error = error as? LAError else {
        self = .localAuthentication(code: (error as NSError).code)
        return
      }

      switch error.code {
      case .authenticationFailed:
        self = .authenticationFailed
      case .appCancel:
        self = .appCancel
      case .biometryDisconnected:
        self = .biometryDisconnected
      case .biometryLockout:
        self = .biometryLockout
      case .biometryNotAvailable:
        self = .biometryNotAvailable
      case .biometryNotEnrolled:
        self = .biometryNotEnrolled
      case .touchIDNotAvailable:
        self = .biometryNotAvailable
      case .touchIDNotEnrolled:
        self = .biometryNotEnrolled
      case .touchIDLockout:
        self = .biometryLockout
      case .invalidContext:
        self = .invalidContext
      case .notInteractive:
        self = .notInteractive
      case .passcodeNotSet:
        self = .passcodeNotSet
      case .systemCancel:
        self = .systemCancel
      case .userCancel:
        self = .userCancel
      case .userFallback:
        self = .userFallback
      #if os(macOS)
      case .watchNotAvailable:
        self = .localAuthentication(code: error.errorCode)
      #endif
      case .biometryNotPaired, .invalidDimensions:
        self = .localAuthentication(code: error.errorCode)
      @unknown default:
        self = .localAuthentication(code: error.errorCode)
      }
    }
  }

  public enum TestError: Swift.Error, Sendable, Equatable {
    case unhandledAuthentication
  }

  /// Test handle with configurable returns, call counters, and local availability state.
  public final class Test: AuthHandle.Local, @unchecked Sendable {
    private let lock = NSLock()
    private var availabilityByPolicy: [Policy: Availability] = [:]
    private var authenticationResults: [(Policy?, Swift.Result<Result, Swift.Error>)] = []
    private var queuedAuthenticationResults: [Swift.Result<Result, Swift.Error>] = []
    private var recordedAuthenticationCalls: [AuthenticationCall] = []
    private var storedBiometryType: BiometryType = .none

    public override init() {
      super.init()
    }

    override public var biometryType: BiometryType {
      lock.withLock { storedBiometryType }
    }

    public var authenticationCallCount: Int {
      lock.withLock { recordedAuthenticationCalls.count }
    }

    public var authenticationCalls: [AuthenticationCall] {
      lock.withLock { recordedAuthenticationCalls }
    }

    public func setBiometryType(_ biometryType: BiometryType) {
      lock.withLock {
        storedBiometryType = biometryType
      }
    }

    public func setAvailability(_ availability: Availability, for policy: Policy) {
      lock.withLock {
        availabilityByPolicy[policy] = availability
      }
    }

    public func setAuthenticationResult(_ result: Result, for policy: Policy? = nil) {
      setAuthenticationResult(.success(result), for: policy)
    }

    public func setAuthenticationError(_ error: Swift.Error, for policy: Policy? = nil) {
      setAuthenticationResult(.failure(error), for: policy)
    }

    public func enqueueAuthenticationResult(_ result: Result) {
      enqueueAuthenticationResult(.success(result))
    }

    public func enqueueAuthenticationError(_ error: Swift.Error) {
      enqueueAuthenticationResult(.failure(error))
    }

    override public func canAuthenticate(policy: Policy = .deviceOwner) -> Availability {
      lock.withLock {
        availabilityByPolicy[policy] ?? Availability(
          isAvailable: false,
          policy: policy,
          biometryType: storedBiometryType,
          error: nil
        )
      }
    }

    override public func authenticate(
      reason: String,
      policy: Policy = .deviceOwner,
      options: PromptOptions = PromptOptions()
    ) async throws -> Result {
      let result = lock.withLock {
        recordedAuthenticationCalls.append(AuthenticationCall(
          reason: reason,
          policy: policy,
          options: options
        ))

        if !queuedAuthenticationResults.isEmpty {
          return queuedAuthenticationResults.removeFirst()
        }

        if let exact = authenticationResults.last(where: { $0.0 == policy }) {
          return exact.1
        }

        if let fallback = authenticationResults.last(where: { $0.0 == nil }) {
          return fallback.1
        }

        return .failure(TestError.unhandledAuthentication)
      }

      return try result.get()
    }

    override public func authenticate(
      accessControl: SecAccessControl,
      operation: AccessControlOperation = .useItem,
      reason: String,
      options: PromptOptions = PromptOptions()
    ) async throws -> Result {
      try await authenticate(reason: reason, policy: .deviceOwner, options: options)
    }

    private func setAuthenticationResult(
      _ result: Swift.Result<Result, Swift.Error>,
      for policy: Policy?
    ) {
      lock.withLock {
        authenticationResults.append((policy, result))
      }
    }

    private func enqueueAuthenticationResult(_ result: Swift.Result<Result, Swift.Error>) {
      lock.withLock {
        queuedAuthenticationResults.append(result)
      }
    }
  }
}
