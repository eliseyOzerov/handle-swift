import Foundation

/// A stable identifier for a generic Keychain password item.
public struct KeychainKey: Hashable, Sendable {
  public var service: String
  public var label: String
  public var account: String?

  public init(service: String, label: String, account: String? = nil) {
    self.service = service
    self.label = label
    self.account = account
  }

  /// Creates a generic password key from a service and label.
  public static func service(
    _ service: String,
    _ label: String,
    account: String? = nil
  ) -> KeychainKey {
    KeychainKey(service: service, label: label, account: account)
  }

  var attributes: Keychain.Password.Attributes {
    .service(service, label: label, account: account)
  }
}

/// Shared operations supported by the production and test Keychain handles.
public protocol KeychainHandling: Sendable {
  func set(_ data: Data, for key: KeychainKey) throws
  func data(for key: KeychainKey) throws -> Data?
  func delete(_ key: KeychainKey) throws
}

public extension KeychainHandling {
  func set(_ value: String, for key: KeychainKey) throws {
    try set(Data(value.utf8), for: key)
  }

  func string(for key: KeychainKey) throws -> String? {
    guard let data = try data(for: key) else {
      return nil
    }

    guard let string = String(data: data, encoding: .utf8) else {
      throw KeychainError.decode
    }

    return string
  }
}

/// An app-shaped handle for generic password items in Security.framework Keychain.
public final class KeychainHandle: KeychainHandling {
  public static let shared = KeychainHandle()

  private let keychain: Keychain

  public init(keychain: Keychain = .shared) {
    self.keychain = keychain
  }

  public func set(_ data: Data, for key: KeychainKey) throws {
    try Keychain.Password().save(data, for: key.attributes)
  }

  public func data(for key: KeychainKey) throws -> Data? {
    do {
      return try Keychain.Password().find(key.attributes).data
    } catch KeychainError.itemNotFound {
      return nil
    }
  }

  public func delete(_ key: KeychainKey) throws {
    try keychain.delete(key.attributes)
  }
}
