import Foundation
import Security

extension Keychain {
  /// Namespace for cryptographic key Keychain operations.
  public enum Key {}
}

extension Keychain.Key {
  struct Kind {
    func toDict() -> KeychainDictionary {
      [String(kSecClass): kSecClassKey]
    }
  }

  /// Key value supplied to add, update, and save operations.
  public struct Value {
    public var reference: SecKey

    public init(reference: SecKey) {
      self.reference = reference
    }

    func toDict() -> KeychainDictionary {
      [String(kSecValueRef): reference]
    }
  }

  struct Return {
    var reference: Bool = true
    var attributes: Bool = true
    var persistentReference: Bool = true

    func toDict() -> KeychainDictionary {
      [
        String(kSecReturnRef): reference,
        String(kSecReturnAttributes): attributes,
        String(kSecReturnPersistentRef): persistentReference,
      ]
    }
  }

  /// Key reference and attributes returned from `Keychain.Key.find`.
  public struct Result {
    public var reference: SecKey
    public var persistentReference: Data?
    public var attributes: Attributes

    public init(reference: SecKey, persistentReference: Data? = nil, attributes: Attributes) {
      self.reference = reference
      self.persistentReference = persistentReference
      self.attributes = attributes
    }

    init(dictionary: KeychainDictionary) throws {
      guard
        let value = dictionary[String(kSecValueRef)],
        CFGetTypeID(value as CFTypeRef) == SecKeyGetTypeID()
      else {
        throw KeychainError.decode
      }

      reference = value as! SecKey
      persistentReference = dictionary[String(kSecValuePersistentRef)] as? Data
      attributes = Attributes(dictionary: dictionary)
    }
  }

  /// Attributes for key Keychain items.
  public struct Attributes {
    public var general: Keychain.Attributes?
    public var keyClass: KeyClass?
    public var applicationLabel: Data?
    public var applicationTag: Data?
    public var keyType: KeyType?
    public var keySizeInBits: Int?
    public var effectiveKeySize: Int?
    public var tokenID: TokenID?
    public var isPermanent: Bool?
    public var isSensitive: Bool?
    public var isExtractable: Bool?
    public var canEncrypt: Bool?
    public var canDecrypt: Bool?
    public var canDerive: Bool?
    public var canSign: Bool?
    public var canVerify: Bool?
    public var canWrap: Bool?
    public var canUnwrap: Bool?

    public init(
      general: Keychain.Attributes? = nil,
      keyClass: KeyClass? = nil,
      applicationLabel: Data? = nil,
      applicationTag: Data? = nil,
      keyType: KeyType? = nil,
      keySizeInBits: Int? = nil,
      effectiveKeySize: Int? = nil,
      tokenID: TokenID? = nil,
      isPermanent: Bool? = nil,
      isSensitive: Bool? = nil,
      isExtractable: Bool? = nil,
      canEncrypt: Bool? = nil,
      canDecrypt: Bool? = nil,
      canDerive: Bool? = nil,
      canSign: Bool? = nil,
      canVerify: Bool? = nil,
      canWrap: Bool? = nil,
      canUnwrap: Bool? = nil
    ) {
      self.general = general
      self.keyClass = keyClass
      self.applicationLabel = applicationLabel
      self.applicationTag = applicationTag
      self.keyType = keyType
      self.keySizeInBits = keySizeInBits
      self.effectiveKeySize = effectiveKeySize
      self.tokenID = tokenID
      self.isPermanent = isPermanent
      self.isSensitive = isSensitive
      self.isExtractable = isExtractable
      self.canEncrypt = canEncrypt
      self.canDecrypt = canDecrypt
      self.canDerive = canDerive
      self.canSign = canSign
      self.canVerify = canVerify
      self.canWrap = canWrap
      self.canUnwrap = canUnwrap
    }

    init(dictionary: KeychainDictionary) {
      general = Keychain.Attributes(dictionary: dictionary)
      keyClass = KeyClass(value: dictionary[String(kSecAttrKeyClass)])
      applicationLabel = dictionary[String(kSecAttrApplicationLabel)] as? Data
      applicationTag = dictionary[String(kSecAttrApplicationTag)] as? Data
      keyType = KeyType(value: dictionary[String(kSecAttrKeyType)])
      keySizeInBits = dictionary[String(kSecAttrKeySizeInBits)] as? Int
      effectiveKeySize = dictionary[String(kSecAttrEffectiveKeySize)] as? Int
      tokenID = TokenID(value: dictionary[String(kSecAttrTokenID)])
      isPermanent = dictionary[String(kSecAttrIsPermanent)] as? Bool
      isSensitive = dictionary[String(kSecAttrIsSensitive)] as? Bool
      isExtractable = dictionary[String(kSecAttrIsExtractable)] as? Bool
      canEncrypt = dictionary[String(kSecAttrCanEncrypt)] as? Bool
      canDecrypt = dictionary[String(kSecAttrCanDecrypt)] as? Bool
      canDerive = dictionary[String(kSecAttrCanDerive)] as? Bool
      canSign = dictionary[String(kSecAttrCanSign)] as? Bool
      canVerify = dictionary[String(kSecAttrCanVerify)] as? Bool
      canWrap = dictionary[String(kSecAttrCanWrap)] as? Bool
      canUnwrap = dictionary[String(kSecAttrCanUnwrap)] as? Bool
    }

    func toDict() -> KeychainDictionary {
      var query = general?.toDict() ?? [:]
      query.set(kSecAttrKeyClass, keyClass?.value)
      query.set(kSecAttrApplicationLabel, applicationLabel)
      query.set(kSecAttrApplicationTag, applicationTag)
      query.set(kSecAttrKeyType, keyType?.value)
      query.set(kSecAttrKeySizeInBits, keySizeInBits)
      query.set(kSecAttrEffectiveKeySize, effectiveKeySize)
      query.set(kSecAttrTokenID, tokenID?.value)
      query.set(kSecAttrIsPermanent, isPermanent)
      query.set(kSecAttrIsSensitive, isSensitive)
      query.set(kSecAttrIsExtractable, isExtractable)
      query.set(kSecAttrCanEncrypt, canEncrypt)
      query.set(kSecAttrCanDecrypt, canDecrypt)
      query.set(kSecAttrCanDerive, canDerive)
      query.set(kSecAttrCanSign, canSign)
      query.set(kSecAttrCanVerify, canVerify)
      query.set(kSecAttrCanWrap, canWrap)
      query.set(kSecAttrCanUnwrap, canUnwrap)
      return query
    }

    /// Key class values used by `Keychain.Key.Attributes` and `Keychain.Identity.Attributes`.
    public enum KeyClass: Equatable {
      case `public`
      case `private`
      case symmetric

      var value: CFString {
        switch self {
        case .public: kSecAttrKeyClassPublic
        case .private: kSecAttrKeyClassPrivate
        case .symmetric: kSecAttrKeyClassSymmetric
        }
      }

      init?(value: Any?) {
        guard let value = keychainString(value) else { return nil }
        switch value {
        case String(kSecAttrKeyClassPublic): self = .public
        case String(kSecAttrKeyClassPrivate): self = .private
        case String(kSecAttrKeyClassSymmetric): self = .symmetric
        default: return nil
        }
      }
    }

    /// Key type values used by `Keychain.Key.Attributes` and `Keychain.Identity.Attributes`.
    public enum KeyType: Equatable {
      case rsa
      case ellipticCurveSECPrimeRandom

      var value: CFString {
        switch self {
        case .rsa: kSecAttrKeyTypeRSA
        case .ellipticCurveSECPrimeRandom: kSecAttrKeyTypeECSECPrimeRandom
        }
      }

      init?(value: Any?) {
        guard let value = keychainString(value) else { return nil }
        switch value {
        case String(kSecAttrKeyTypeRSA): self = .rsa
        case String(kSecAttrKeyTypeECSECPrimeRandom): self = .ellipticCurveSECPrimeRandom
        default: return nil
        }
      }
    }

    /// Key token identifiers used by `Keychain.Key.Attributes` and `Keychain.Identity.Attributes`.
    public enum TokenID: Equatable {
      case secureEnclave

      var value: CFString {
        kSecAttrTokenIDSecureEnclave
      }

      init?(value: Any?) {
        guard keychainString(value) == String(kSecAttrTokenIDSecureEnclave) else {
          return nil
        }
        self = .secureEnclave
      }
    }
  }

  /// Adds a key item and returns the stored reference plus attributes.
  @discardableResult
  public static func add(
    _ reference: SecKey,
    with attributes: Attributes = Attributes()
  ) throws -> Result {
    var query: KeychainDictionary = [:]
    query.merge(Value(reference: reference).toDict())
    query.merge(Kind().toDict())
    query.merge(attributes.toDict())
    query.merge(Return().toDict())

    var result: AnyObject?
    let status = SecItemAdd(query as CFDictionary, &result)

    guard status == errSecSuccess else {
      throw keychainError(status)
    }

    return try decodeResult(result)
  }

  /// Finds a key item matching the supplied attributes.
  public static func find(
    _ attributes: Attributes = Attributes(),
    matching: Keychain.Match = Keychain.Match()
  ) throws -> Result {
    var query: KeychainDictionary = [:]
    query.merge(Kind().toDict())
    query.merge(attributes.toDict())
    query.merge(matching.toDict())
    query.merge(Return().toDict())

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    guard status == errSecSuccess else {
      throw keychainError(status)
    }

    return try decodeResult(result)
  }

  /// Updates key data for an existing item.
  public static func update(_ value: Value, for attributes: Attributes) throws {
    var query: KeychainDictionary = [:]
    query.merge(Kind().toDict())
    query.merge(attributes.toDict())

    let status = SecItemUpdate(
      query as CFDictionary,
      value.toDict() as CFDictionary
    )

    guard status == errSecSuccess else {
      throw keychainError(status)
    }
  }

  /// Adds a key item or updates it when it already exists.
  public static func save(
    _ reference: SecKey,
    with attributes: Attributes = Attributes()
  ) throws {
    try save(Value(reference: reference), for: attributes)
  }

  /// Adds a key value or updates it when it already exists.
  public static func save(_ value: Value, for attributes: Attributes) throws {
    do {
      try add(value.reference, with: attributes)
    } catch KeychainError.duplicateItem {
      try update(value, for: attributes)
    }
  }

  /// Deletes key items matching the supplied attributes.
  public static func delete(_ attributes: Attributes, matching: Keychain.Match? = nil) throws {
    var query: KeychainDictionary = [:]
    query.merge(Kind().toDict())
    query.merge(attributes.toDict())
    if let matching {
      query.merge(matching.toDict())
    }

    let status = SecItemDelete(query as CFDictionary)

    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw keychainError(status)
    }
  }

  private static func decodeResult(_ result: AnyObject?) throws -> Result {
    guard let dictionary = result as? KeychainDictionary else {
      throw KeychainError.decode
    }

    return try Result(dictionary: dictionary)
  }
}
