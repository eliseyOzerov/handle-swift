import Foundation
import Security

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
}

/// Errors thrown by `KeychainHandle`.
public enum KeychainHandleError: Error, Equatable, Sendable {
  case invalidStringData
  case unexpectedResult
  case unhandledStatus(OSStatus)
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
      throw KeychainHandleError.invalidStringData
    }

    return string
  }
}

/// An app-shaped handle for generic password items in Security.framework Keychain.
public final class KeychainHandle: KeychainHandling {
  public static let shared = KeychainHandle()

  public init() {}

  public func set(_ data: Data, for key: KeychainKey) throws {
    do {
      try add(data, for: key)
    } catch KeychainHandleError.unhandledStatus(errSecDuplicateItem) {
      try update(data, for: key)
    }
  }

  public func data(for key: KeychainKey) throws -> Data? {
    var query = key.query()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    switch status {
    case errSecSuccess:
      guard let data = result as? Data else {
        throw KeychainHandleError.unexpectedResult
      }
      return data
    case errSecItemNotFound:
      return nil
    default:
      throw KeychainHandleError.unhandledStatus(status)
    }
  }

  public func delete(_ key: KeychainKey) throws {
    let status = SecItemDelete(key.query() as CFDictionary)

    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw KeychainHandleError.unhandledStatus(status)
    }
  }

  private func add(_ data: Data, for key: KeychainKey) throws {
    var query = key.query()
    query[kSecValueData as String] = data
    query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    let status = SecItemAdd(query as CFDictionary, nil)

    guard status == errSecSuccess else {
      throw KeychainHandleError.unhandledStatus(status)
    }
  }

  private func update(_ data: Data, for key: KeychainKey) throws {
    let status = SecItemUpdate(
      key.query() as CFDictionary,
      [kSecValueData as String: data] as CFDictionary
    )

    guard status == errSecSuccess else {
      throw KeychainHandleError.unhandledStatus(status)
    }
  }
}

private extension KeychainKey {
  func query() -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrGeneric as String: Data(label.utf8),
    ]

    if let account {
      query[kSecAttrAccount as String] = account
    }

    return query
  }
}
