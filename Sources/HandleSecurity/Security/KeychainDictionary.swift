import Foundation
import Security

typealias KeychainDictionary = [String: Any]

extension KeychainDictionary {
  mutating func set(_ key: CFString, _ value: Any?) {
    if let value {
      self[key as String] = value
    }
  }

  mutating func merge(_ other: KeychainDictionary) {
    merge(other) { _, new in new }
  }
}

func keychainError(_ status: OSStatus) -> SecurityHandle.Error {
  SecurityHandle.Error.fromValue(status) ?? .unknown(status)
}

func keychainString(_ value: Any?) -> String? {
  if let string = value as? String {
    return string
  }

  guard let value else {
    return nil
  }

  return String(describing: value)
}
