import Foundation
import Security

/// Namespace for Security.framework Keychain helpers, including `SecurityHandle.Keychain.Password` and `SecurityHandle.Keychain.Key`.
extension SecurityHandle {
public final class Keychain: Sendable {
  private init() {}
  public static let shared = Keychain()

  /// Saves a generic password string using `SecurityHandle.Keychain.Password`.
  public func save(_ value: String, for query: Password.Attributes) throws {
    try Password().save(Data(value.utf8), for: query)
  }

  /// Finds a generic password string using `SecurityHandle.Keychain.Password`.
  public func find(
    _ query: Password.Attributes,
    matching: SecurityHandle.Keychain.Match = SecurityHandle.Keychain.Match()
  ) throws -> String? {
    do {
      let result = try Password().find(query, matching: matching)
      return String(data: result.data, encoding: .utf8)
    } catch SecurityHandle.Error.itemNotFound {
      return nil
    }
  }

  /// Deletes a generic password using `SecurityHandle.Keychain.Password`.
  public func delete(_ query: Password.Attributes, matching: SecurityHandle.Keychain.Match? = nil) throws {
    try Password().delete(query, matching: matching)
  }
}
}

extension SecurityHandle.Keychain {
  /// Shared Keychain item attributes used by password, certificate, identity, and key queries.
  public struct Attributes {
    public var accessibility: AccessPolicy?
    public var accessControl: SecAccessControl?
    public var accessGroup: AccessGroup?
    public var synchronizable: Synchronizability?
    public var creationDate: Foundation.Date?
    public var modificationDate: Foundation.Date?
    public var description: String?
    public var comment: String?
    public var creator: Int?
    public var type: Int?
    public var label: String?
    public var isInvisible: Bool?
    public var isNegative: Bool?
    public var syncViewHint: String?
    public var persistantReference: Data?
    public var persistentReference: Data?

    public init(
      accessibility: AccessPolicy? = .afterFirstUnlockThisDeviceOnly,
      accessControl: SecAccessControl? = nil,
      accessGroup: AccessGroup? = nil,
      synchronizable: Synchronizability? = nil,
      creationDate: Foundation.Date? = nil,
      modificationDate: Foundation.Date? = nil,
      description: String? = nil,
      comment: String? = nil,
      creator: Int? = nil,
      type: Int? = nil,
      label: String? = nil,
      isInvisible: Bool? = nil,
      isNegative: Bool? = nil,
      syncViewHint: String? = nil,
      persistantReference: Data? = nil,
      persistentReference: Data? = nil
    ) {
      self.accessibility = accessibility
      self.accessControl = accessControl
      self.accessGroup = accessGroup
      self.synchronizable = synchronizable
      self.creationDate = creationDate
      self.modificationDate = modificationDate
      self.description = description
      self.comment = comment
      self.creator = creator
      self.type = type
      self.label = label
      self.isInvisible = isInvisible
      self.isNegative = isNegative
      self.syncViewHint = syncViewHint
      self.persistantReference = persistantReference
      self.persistentReference = persistentReference
    }

    init(dictionary: KeychainDictionary) {
      accessibility = AccessPolicy(value: dictionary[String(kSecAttrAccessible)])
      accessControl = dictionary[String(kSecAttrAccessControl)] as! SecAccessControl?
      accessGroup = AccessGroup(value: dictionary[String(kSecAttrAccessGroup)])
      synchronizable = Synchronizability(value: dictionary[String(kSecAttrSynchronizable)])
      creationDate = dictionary[String(kSecAttrCreationDate)] as? Foundation.Date
      modificationDate = dictionary[String(kSecAttrModificationDate)] as? Foundation.Date
      description = dictionary[String(kSecAttrDescription)] as? String
      comment = dictionary[String(kSecAttrComment)] as? String
      creator = dictionary[String(kSecAttrCreator)] as? Int
      type = dictionary[String(kSecAttrType)] as? Int
      label = dictionary[String(kSecAttrLabel)] as? String
      isInvisible = dictionary[String(kSecAttrIsInvisible)] as? Bool
      isNegative = dictionary[String(kSecAttrIsNegative)] as? Bool
      syncViewHint = dictionary[String(kSecAttrSyncViewHint)] as? String
      persistantReference = dictionary[String(kSecAttrPersistantReference)] as? Data
      persistentReference = dictionary[String(kSecAttrPersistentReference)] as? Data
    }

    func toDict() -> KeychainDictionary {
      var query: KeychainDictionary = [:]
      query.set(kSecAttrAccessible, accessibility?.value)
      query.set(kSecAttrAccessControl, accessControl)
      query.set(kSecAttrAccessGroup, accessGroup?.value)
      query.set(kSecAttrSynchronizable, synchronizable?.value)
      query.set(kSecAttrCreationDate, creationDate)
      query.set(kSecAttrModificationDate, modificationDate)
      query.set(kSecAttrDescription, description)
      query.set(kSecAttrComment, comment)
      query.set(kSecAttrCreator, creator)
      query.set(kSecAttrType, type)
      query.set(kSecAttrLabel, label)
      query.set(kSecAttrIsInvisible, isInvisible)
      query.set(kSecAttrIsNegative, isNegative)
      query.set(kSecAttrSyncViewHint, syncViewHint)
      query.set(kSecAttrPersistantReference, persistantReference)
      query.set(kSecAttrPersistentReference, persistentReference)
      return query
    }
  }
}

extension SecurityHandle.Keychain {
  /// Accessibility policies for `SecurityHandle.Keychain.Attributes`.
  public enum AccessPolicy: Equatable {
    case whenPasscodeSetThisDeviceOnly
    case whenUnlockedThisDeviceOnly
    case whenUnlocked
    case afterFirstUnlockThisDeviceOnly
    case afterFirstUnlock

    var value: CFString {
      switch self {
      case .whenPasscodeSetThisDeviceOnly: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
      case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      case .whenUnlocked: kSecAttrAccessibleWhenUnlocked
      case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
      case .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock
      }
    }

    init?(value: Any?) {
      guard let value = keychainString(value) else { return nil }
      switch value {
      case String(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly): self = .whenPasscodeSetThisDeviceOnly
      case String(kSecAttrAccessibleWhenUnlockedThisDeviceOnly): self = .whenUnlockedThisDeviceOnly
      case String(kSecAttrAccessibleWhenUnlocked): self = .whenUnlocked
      case String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly): self = .afterFirstUnlockThisDeviceOnly
      case String(kSecAttrAccessibleAfterFirstUnlock): self = .afterFirstUnlock
      default: return nil
      }
    }
  }

  /// Access group values for sharing Keychain items across apps.
  public enum AccessGroup: Equatable {
    case externalToken
    case group(String)

    var value: Any {
      switch self {
      case .externalToken: kSecAttrAccessGroupToken
      case .group(let group): group
      }
    }

    init?(value: Any?) {
      guard let string = keychainString(value) else { return nil }
      if string == String(kSecAttrAccessGroupToken) {
        self = .externalToken
      } else {
        self = .group(string)
      }
    }
  }

  /// Synchronization policy for `SecurityHandle.Keychain.Attributes`.
  public enum Synchronizability: Equatable {
    case enabled
    case disabled
    case any

    var value: Any {
      switch self {
      case .enabled: true
      case .disabled: false
      case .any: kSecAttrSynchronizableAny
      }
    }

    init?(value: Any?) {
      switch value {
      case let value as Bool where value: self = .enabled
      case let value as Bool where !value: self = .disabled
      case let value where keychainString(value) == String(kSecAttrSynchronizableAny): self = .any
      default: return nil
      }
    }
  }
}

extension SecurityHandle.Keychain {
  /// Search filters for Keychain copy and read operations.
  public struct Match {
    public var policy: SecPolicy?
    public var itemList: [Any]?
    public var caseInsensitive: Bool?
    public var issuers: [Data]?
    public var emailAddressIfPresent: String?
    public var subjectContains: String?
    public var trustedOnly: Bool?
    public var validOnDate: Foundation.Date?
    public var limit: Limit

    public init(
      policy: SecPolicy? = nil,
      itemList: [Any]? = nil,
      caseInsensitive: Bool? = nil,
      issuers: [Data]? = nil,
      emailAddressIfPresent: String? = nil,
      subjectContains: String? = nil,
      trustedOnly: Bool? = nil,
      validOnDate: Foundation.Date? = nil,
      limit: Limit = .one
    ) {
      self.policy = policy
      self.itemList = itemList
      self.caseInsensitive = caseInsensitive
      self.issuers = issuers
      self.emailAddressIfPresent = emailAddressIfPresent
      self.subjectContains = subjectContains
      self.trustedOnly = trustedOnly
      self.validOnDate = validOnDate
      self.limit = limit
    }

    func toDict() -> KeychainDictionary {
      var query: KeychainDictionary = [:]
      query.set(kSecMatchPolicy, policy)
      query.set(kSecMatchItemList, itemList)
      query.set(kSecMatchCaseInsensitive, caseInsensitive)
      query.set(kSecMatchIssuers, issuers)
      query.set(kSecMatchEmailAddressIfPresent, emailAddressIfPresent)
      query.set(kSecMatchSubjectContains, subjectContains)
      query.set(kSecMatchTrustedOnly, trustedOnly)
      query.set(kSecMatchValidOnDate, validOnDate)
      query.set(kSecMatchLimit, limit.value)
      return query
    }

    /// Limit for the number of values returned by `SecurityHandle.Keychain.Match`.
    public enum Limit: Equatable {
      case one
      case all

      var value: CFString {
        switch self {
        case .one: kSecMatchLimitOne
        case .all: kSecMatchLimitAll
        }
      }
    }
  }
}
