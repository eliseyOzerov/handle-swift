import Foundation
import Security

extension Keychain {
  /// Namespace for certificate Keychain operations.
  public enum Certificate {}
}

extension Keychain.Certificate {
  struct Kind {
    func toDict() -> KeychainDictionary {
      [kSecClass as String: kSecClassCertificate]
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

  /// Certificate value supplied to add, update, and save operations.
  public struct Value {
    public var reference: SecCertificate?
    public var persistentReference: Data?

    public init(reference: SecCertificate? = nil, persistentReference: Data? = nil) {
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

  /// Certificate reference and attributes returned from `Keychain.Certificate.find`.
  public struct Result {
    public var reference: SecCertificate
    public var persistentReference: Data?
    public var attributes: Attributes

    public init(reference: SecCertificate, persistentReference: Data? = nil, attributes: Attributes) {
      self.reference = reference
      self.persistentReference = persistentReference
      self.attributes = attributes
    }

    init(dictionary: KeychainDictionary) throws {
      guard
        let value = dictionary[kSecValueRef as String],
        CFGetTypeID(value as CFTypeRef) == SecCertificateGetTypeID()
      else {
        throw KeychainError.decode
      }

      reference = value as! SecCertificate
      persistentReference = dictionary[kSecValuePersistentRef as String] as? Data
      attributes = Attributes(dictionary: dictionary)
    }
  }

  /// Attributes for certificate Keychain items.
  public struct Attributes {
    public var general: Keychain.Attributes?
    public var subject: Data?
    public var issuer: Data?
    public var serialNumber: Data?
    public var subjectKeyID: Data?
    public var publicKeyHash: Data?
    public var certificateType: UInt32?
    public var certificateEncoding: UInt32?

    public init(
      general: Keychain.Attributes? = nil,
      subject: Data? = nil,
      issuer: Data? = nil,
      serialNumber: Data? = nil,
      subjectKeyID: Data? = nil,
      publicKeyHash: Data? = nil,
      certificateType: UInt32? = nil,
      certificateEncoding: UInt32? = nil
    ) {
      self.general = general
      self.subject = subject
      self.issuer = issuer
      self.serialNumber = serialNumber
      self.subjectKeyID = subjectKeyID
      self.publicKeyHash = publicKeyHash
      self.certificateType = certificateType
      self.certificateEncoding = certificateEncoding
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
      return query
    }
  }

  /// Adds a certificate item and returns the stored reference plus attributes.
  @discardableResult
  public static func add(
    _ reference: SecCertificate,
    with attributes: Attributes = Attributes()
  ) throws -> Result {
    try add(Value(reference: reference), with: attributes)
  }

  /// Adds a certificate value and returns the stored reference plus attributes.
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

  /// Finds a certificate item matching the supplied attributes.
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

  /// Updates certificate data for an existing item.
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

  /// Adds a certificate item or updates it when it already exists.
  public static func save(
    _ reference: SecCertificate,
    with attributes: Attributes = Attributes()
  ) throws {
    try save(Value(reference: reference), for: attributes)
  }

  /// Adds a certificate value or updates it when it already exists.
  public static func save(_ value: Value, for attributes: Attributes) throws {
    do {
      try add(value, with: attributes)
    } catch KeychainError.duplicateItem {
      try update(value, for: attributes)
    }
  }

  /// Deletes certificate items matching the supplied attributes.
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
