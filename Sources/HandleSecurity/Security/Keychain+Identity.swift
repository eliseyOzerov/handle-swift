import Foundation
import Security

extension Keychain {
  /// Namespace for identity Keychain operations.
  public enum Identity {}
}

extension Keychain.Identity {
  struct Kind {
    func toDict() -> KeychainDictionary {
      [kSecClass as String: kSecClassIdentity]
    }
  }

  struct Return {
    var reference: Bool = true
    var attributes: Bool = true
    var persistentReference: Bool = true

    func toDict() -> KeychainDictionary {
      [
        kSecReturnRef as String: reference,
        kSecReturnAttributes as String: attributes,
        kSecReturnPersistentRef as String: persistentReference,
      ]
    }
  }

  /// Identity value supplied to add, update, and save operations.
  public struct Value {
    public var reference: SecIdentity?
    public var persistentReference: Data?

    public init(reference: SecIdentity? = nil, persistentReference: Data? = nil) {
      self.reference = reference
      self.persistentReference = persistentReference
    }

    func toDict() -> KeychainDictionary {
      var query: KeychainDictionary = [:]
      query.set(kSecValueRef, reference)
      query.set(kSecValuePersistentRef, persistentReference)
      return query
    }
  }

  /// Identity reference and attributes returned from `Keychain.Identity.find`.
  public struct Result {
    public var reference: SecIdentity
    public var persistentReference: Data?
    public var attributes: Attributes

    public init(reference: SecIdentity, persistentReference: Data? = nil, attributes: Attributes) {
      self.reference = reference
      self.persistentReference = persistentReference
      self.attributes = attributes
    }

    init(dictionary: KeychainDictionary) throws {
      guard
        let value = dictionary[kSecValueRef as String],
        CFGetTypeID(value as CFTypeRef) == SecIdentityGetTypeID()
      else {
        throw KeychainError.decode
      }

      reference = value as! SecIdentity
      persistentReference = dictionary[kSecValuePersistentRef as String] as? Data
      attributes = Attributes(dictionary: dictionary)
    }
  }

  /// Attributes for identity Keychain items.
  public struct Attributes {
    public var general: Keychain.Attributes?
    public var subject: Data?
    public var issuer: Data?
    public var serialNumber: Data?
    public var subjectKeyID: Data?
    public var publicKeyHash: Data?
    public var certificateType: UInt32?
    public var certificateEncoding: UInt32?
    public var keyClass: Keychain.Key.Attributes.KeyClass?
    public var applicationLabel: Data?
    public var isPermanent: Bool?
    public var isSensitive: Bool?
    public var isExtractable: Bool?
    public var applicationTag: Data?
    public var keyType: Keychain.Key.Attributes.KeyType?
    public var keySizeInBits: Int?
    public var effectiveKeySize: Int?
    public var canEncrypt: Bool?
    public var canDecrypt: Bool?
    public var canDerive: Bool?
    public var canSign: Bool?
    public var canVerify: Bool?
    public var canWrap: Bool?
    public var canUnwrap: Bool?
    public var tokenID: Keychain.Key.Attributes.TokenID?

    public init(
      general: Keychain.Attributes? = nil,
      subject: Data? = nil,
      issuer: Data? = nil,
      serialNumber: Data? = nil,
      subjectKeyID: Data? = nil,
      publicKeyHash: Data? = nil,
      certificateType: UInt32? = nil,
      certificateEncoding: UInt32? = nil,
      keyClass: Keychain.Key.Attributes.KeyClass? = nil,
      applicationLabel: Data? = nil,
      isPermanent: Bool? = nil,
      isSensitive: Bool? = nil,
      isExtractable: Bool? = nil,
      applicationTag: Data? = nil,
      keyType: Keychain.Key.Attributes.KeyType? = nil,
      keySizeInBits: Int? = nil,
      effectiveKeySize: Int? = nil,
      canEncrypt: Bool? = nil,
      canDecrypt: Bool? = nil,
      canDerive: Bool? = nil,
      canSign: Bool? = nil,
      canVerify: Bool? = nil,
      canWrap: Bool? = nil,
      canUnwrap: Bool? = nil,
      tokenID: Keychain.Key.Attributes.TokenID? = nil
    ) {
      self.general = general
      self.subject = subject
      self.issuer = issuer
      self.serialNumber = serialNumber
      self.subjectKeyID = subjectKeyID
      self.publicKeyHash = publicKeyHash
      self.certificateType = certificateType
      self.certificateEncoding = certificateEncoding
      self.keyClass = keyClass
      self.applicationLabel = applicationLabel
      self.isPermanent = isPermanent
      self.isSensitive = isSensitive
      self.isExtractable = isExtractable
      self.applicationTag = applicationTag
      self.keyType = keyType
      self.keySizeInBits = keySizeInBits
      self.effectiveKeySize = effectiveKeySize
      self.canEncrypt = canEncrypt
      self.canDecrypt = canDecrypt
      self.canDerive = canDerive
      self.canSign = canSign
      self.canVerify = canVerify
      self.canWrap = canWrap
      self.canUnwrap = canUnwrap
      self.tokenID = tokenID
    }

    init(dictionary: KeychainDictionary) {
      general = Keychain.Attributes(dictionary: dictionary)
      subject = dictionary[kSecAttrSubject as String] as? Data
      issuer = dictionary[kSecAttrIssuer as String] as? Data
      serialNumber = dictionary[kSecAttrSerialNumber as String] as? Data
      subjectKeyID = dictionary[kSecAttrSubjectKeyID as String] as? Data
      publicKeyHash = dictionary[kSecAttrPublicKeyHash as String] as? Data
      certificateType = dictionary[kSecAttrCertificateType as String] as? UInt32
      certificateEncoding = dictionary[kSecAttrCertificateEncoding as String] as? UInt32
      keyClass = Keychain.Key.Attributes.KeyClass(value: dictionary[kSecAttrKeyClass as String])
      applicationLabel = dictionary[kSecAttrApplicationLabel as String] as? Data
      isPermanent = dictionary[kSecAttrIsPermanent as String] as? Bool
      isSensitive = dictionary[kSecAttrIsSensitive as String] as? Bool
      isExtractable = dictionary[kSecAttrIsExtractable as String] as? Bool
      applicationTag = dictionary[kSecAttrApplicationTag as String] as? Data
      keyType = Keychain.Key.Attributes.KeyType(value: dictionary[kSecAttrKeyType as String])
      keySizeInBits = dictionary[kSecAttrKeySizeInBits as String] as? Int
      effectiveKeySize = dictionary[kSecAttrEffectiveKeySize as String] as? Int
      canEncrypt = dictionary[kSecAttrCanEncrypt as String] as? Bool
      canDecrypt = dictionary[kSecAttrCanDecrypt as String] as? Bool
      canDerive = dictionary[kSecAttrCanDerive as String] as? Bool
      canSign = dictionary[kSecAttrCanSign as String] as? Bool
      canVerify = dictionary[kSecAttrCanVerify as String] as? Bool
      canWrap = dictionary[kSecAttrCanWrap as String] as? Bool
      canUnwrap = dictionary[kSecAttrCanUnwrap as String] as? Bool
      tokenID = Keychain.Key.Attributes.TokenID(value: dictionary[kSecAttrTokenID as String])
    }

    func toDict() -> KeychainDictionary {
      var query = general?.toDict() ?? [:]
      query.set(kSecAttrSubject, subject)
      query.set(kSecAttrIssuer, issuer)
      query.set(kSecAttrSerialNumber, serialNumber)
      query.set(kSecAttrSubjectKeyID, subjectKeyID)
      query.set(kSecAttrPublicKeyHash, publicKeyHash)
      query.set(kSecAttrCertificateType, certificateType)
      query.set(kSecAttrCertificateEncoding, certificateEncoding)
      query.set(kSecAttrKeyClass, keyClass?.value)
      query.set(kSecAttrApplicationLabel, applicationLabel)
      query.set(kSecAttrIsPermanent, isPermanent)
      query.set(kSecAttrIsSensitive, isSensitive)
      query.set(kSecAttrIsExtractable, isExtractable)
      query.set(kSecAttrApplicationTag, applicationTag)
      query.set(kSecAttrKeyType, keyType?.value)
      query.set(kSecAttrKeySizeInBits, keySizeInBits)
      query.set(kSecAttrEffectiveKeySize, effectiveKeySize)
      query.set(kSecAttrCanEncrypt, canEncrypt)
      query.set(kSecAttrCanDecrypt, canDecrypt)
      query.set(kSecAttrCanDerive, canDerive)
      query.set(kSecAttrCanSign, canSign)
      query.set(kSecAttrCanVerify, canVerify)
      query.set(kSecAttrCanWrap, canWrap)
      query.set(kSecAttrCanUnwrap, canUnwrap)
      query.set(kSecAttrTokenID, tokenID?.value)
      return query
    }
  }

  /// Adds an identity item and returns the stored reference plus attributes.
  @discardableResult
  public static func add(
    _ reference: SecIdentity,
    with attributes: Attributes = Attributes()
  ) throws -> Result {
    try add(Value(reference: reference), with: attributes)
  }

  /// Adds an identity value and returns the stored reference plus attributes.
  @discardableResult
  public static func add(
    _ value: Value,
    with attributes: Attributes = Attributes()
  ) throws -> Result {
    var query: KeychainDictionary = [:]
    query.merge(value.toDict())
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

  /// Finds an identity item matching the supplied attributes.
  @discardableResult
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

  /// Updates identity data for an existing item.
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

  /// Adds an identity item or updates it when it already exists.
  public static func save(
    _ reference: SecIdentity,
    with attributes: Attributes = Attributes()
  ) throws {
    try save(Value(reference: reference), for: attributes)
  }

  /// Adds an identity value or updates it when it already exists.
  public static func save(_ value: Value, for attributes: Attributes) throws {
    do {
      try add(value, with: attributes)
    } catch KeychainError.duplicateItem {
      try update(value, for: attributes)
    }
  }

  /// Deletes identity items matching the supplied attributes.
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
