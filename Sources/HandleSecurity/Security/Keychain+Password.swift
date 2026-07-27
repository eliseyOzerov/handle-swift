import Foundation
import Security

extension SecurityHandle.Keychain {
  /// Namespace for generic and internet password Keychain operations.
  public struct Password {
    public init() {}
  }
}

extension SecurityHandle.Keychain.Password {
  struct Value {
    var data: Data

    func toDict() -> KeychainDictionary {
      [String(kSecValueData): data]
    }
  }

  struct Return {
    var data: Bool = true
    var attributes: Bool = true

    func toDict() -> KeychainDictionary {
      [
        String(kSecReturnData): data,
        String(kSecReturnAttributes): attributes,
      ]
    }
  }

  /// Password data and attributes returned from `SecurityHandle.Keychain.Password.find`.
  public struct Result {
    public var data: Data
    public var attributes: Attributes

    public init(data: Data, attributes: Attributes) {
      self.data = data
      self.attributes = attributes
    }

    init(dictionary: KeychainDictionary) throws {
      guard let data = dictionary[String(kSecValueData)] as? Data else {
        throw SecurityHandle.Error.decode
      }
      self.data = data
      attributes = Attributes(dictionary: dictionary)
    }
  }

  /// Password item class used by `SecurityHandle.Keychain.Password.Attributes`.
  public enum Kind: Equatable {
    case generic
    case internet

    var value: CFString {
      switch self {
      case .generic: kSecClassGenericPassword
      case .internet: kSecClassInternetPassword
      }
    }

    init?(value: Any?) {
      guard let value = keychainString(value) else { return nil }
      switch value {
      case String(kSecClassGenericPassword): self = .generic
      case String(kSecClassInternetPassword): self = .internet
      default: return nil
      }
    }
  }

  /// Attributes for generic and internet password Keychain items.
  public struct Attributes {
    public var general: SecurityHandle.Keychain.Attributes?
    public var kind: Kind
    public var service: String?
    public var account: String?
    public var generic: Data?
    public var server: String?
    public var securityDomain: String?
    public var internetProtocol: SecurityHandle.Keychain.InternetProtocol?
    public var authenticationType: SecurityHandle.Keychain.AuthenticationType?
    public var port: Int?
    public var path: String?

    public init(
      general: SecurityHandle.Keychain.Attributes? = nil,
      kind: Kind = .generic,
      service: String? = nil,
      account: String? = nil,
      generic: Data? = nil,
      server: String? = nil,
      securityDomain: String? = nil,
      internetProtocol: SecurityHandle.Keychain.InternetProtocol? = nil,
      authenticationType: SecurityHandle.Keychain.AuthenticationType? = nil,
      port: Int? = nil,
      path: String? = nil
    ) {
      self.general = general
      self.kind = kind
      self.service = service
      self.account = account
      self.generic = generic
      self.server = server
      self.securityDomain = securityDomain
      self.internetProtocol = internetProtocol
      self.authenticationType = authenticationType
      self.port = port
      self.path = path
    }

    init(dictionary: KeychainDictionary) {
      general = SecurityHandle.Keychain.Attributes(dictionary: dictionary)
      kind = Kind(value: dictionary[String(kSecClass)]) ?? .generic
      service = dictionary[String(kSecAttrService)] as? String
      account = dictionary[String(kSecAttrAccount)] as? String
      generic = dictionary[String(kSecAttrGeneric)] as? Data
      server = dictionary[String(kSecAttrServer)] as? String
      securityDomain = dictionary[String(kSecAttrSecurityDomain)] as? String
      internetProtocol = SecurityHandle.Keychain.InternetProtocol(value: dictionary[String(kSecAttrProtocol)])
      authenticationType = SecurityHandle.Keychain.AuthenticationType(value: dictionary[String(kSecAttrAuthenticationType)])
      port = dictionary[String(kSecAttrPort)] as? Int
      path = dictionary[String(kSecAttrPath)] as? String
    }

    /// Creates generic password attributes keyed by opaque data.
    public static func key(_ key: String) -> Attributes {
      Attributes(kind: .generic, generic: Data(key.utf8))
    }

    /// Creates generic password attributes keyed by service, label, and optional account.
    public static func service(
      _ service: String,
      label: String,
      account: String? = nil
    ) -> Attributes {
      Attributes(
        kind: .generic,
        service: service,
        account: account,
        generic: Data(label.utf8)
      )
    }

    /// Creates internet password attributes keyed by server and optional connection metadata.
    public static func server(
      _ server: String,
      account: String? = nil,
      securityDomain: String? = nil,
      internetProtocol: SecurityHandle.Keychain.InternetProtocol? = nil,
      auth: SecurityHandle.Keychain.AuthenticationType? = nil,
      port: Int? = nil,
      path: String? = nil
    ) -> Attributes {
      Attributes(
        kind: .internet,
        account: account,
        server: server,
        securityDomain: securityDomain,
        internetProtocol: internetProtocol,
        authenticationType: auth,
        port: port,
        path: path
      )
    }

    func toDict() -> KeychainDictionary {
      var query = general?.toDict() ?? [:]
      query.set(kSecClass, kind.value)
      query.set(kSecAttrService, service)
      query.set(kSecAttrAccount, account)
      query.set(kSecAttrGeneric, generic)
      query.set(kSecAttrServer, server)
      query.set(kSecAttrSecurityDomain, securityDomain)
      query.set(kSecAttrProtocol, internetProtocol?.value)
      query.set(kSecAttrAuthenticationType, authenticationType?.value)
      query.set(kSecAttrPort, port)
      query.set(kSecAttrPath, path)
      return query
    }
  }

  /// Adds a password item and returns the stored data plus attributes.
  @discardableResult
  public func add(_ value: Data, for attributes: Attributes) throws -> Result {
    var query: KeychainDictionary = [:]
    query.merge(Value(data: value).toDict())
    query.merge(attributes.toDict())
    query.merge(Return().toDict())

    var result: AnyObject?
    let status = SecItemAdd(query as CFDictionary, &result)

    guard status == errSecSuccess else {
      throw keychainError(status)
    }

    return try decodeResult(result)
  }

  /// Finds a password item matching the supplied attributes.
  public func find(
    _ attributes: Attributes,
    matching: SecurityHandle.Keychain.Match = SecurityHandle.Keychain.Match()
  ) throws -> Result {
    var query: KeychainDictionary = [:]
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

  /// Updates password data for an existing item.
  public func update(_ value: Data, for attributes: Attributes) throws {
    let status = SecItemUpdate(
      attributes.toDict() as CFDictionary,
      Value(data: value).toDict() as CFDictionary
    )

    guard status == errSecSuccess else {
      throw keychainError(status)
    }
  }

  /// Adds a password item or updates it when it already exists.
  public func save(_ value: Data, for attributes: Attributes) throws {
    do {
      try add(value, for: attributes)
    } catch SecurityHandle.Error.duplicateItem {
      try update(value, for: attributes)
    }
  }

  /// Deletes password items matching the supplied attributes.
  public func delete(_ attributes: Attributes, matching: SecurityHandle.Keychain.Match? = nil) throws {
    var query = attributes.toDict()
    if let matching {
      query.merge(matching.toDict())
    }

    let status = SecItemDelete(query as CFDictionary)

    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw keychainError(status)
    }
  }

  private func decodeResult(_ result: AnyObject?) throws -> Result {
    guard let dictionary = result as? KeychainDictionary else {
      throw SecurityHandle.Error.decode
    }

    return try Result(dictionary: dictionary)
  }
}

extension SecurityHandle.Keychain {
  /// Internet password protocol values used by `SecurityHandle.Keychain.Password.Attributes`.
  public enum InternetProtocol: Equatable {
    case ftp, ftpAccount, http, irc, nntp, pop3, smtp, socks, imap, ldap
    case appleTalk, afp, telnet, ssh, ftps, https, httpProxy, httpsProxy, ftpProxy
    case smb, rtsp, rtspProxy, daap, eppc, ipp, nntps, ldaps, telnetS, imaps, ircs, pop3S

    var value: CFString {
      switch self {
      case .ftp: kSecAttrProtocolFTP
      case .ftpAccount: kSecAttrProtocolFTPAccount
      case .http: kSecAttrProtocolHTTP
      case .irc: kSecAttrProtocolIRC
      case .nntp: kSecAttrProtocolNNTP
      case .pop3: kSecAttrProtocolPOP3
      case .smtp: kSecAttrProtocolSMTP
      case .socks: kSecAttrProtocolSOCKS
      case .imap: kSecAttrProtocolIMAP
      case .ldap: kSecAttrProtocolLDAP
      case .appleTalk: kSecAttrProtocolAppleTalk
      case .afp: kSecAttrProtocolAFP
      case .telnet: kSecAttrProtocolTelnet
      case .ssh: kSecAttrProtocolSSH
      case .ftps: kSecAttrProtocolFTPS
      case .https: kSecAttrProtocolHTTPS
      case .httpProxy: kSecAttrProtocolHTTPProxy
      case .httpsProxy: kSecAttrProtocolHTTPSProxy
      case .ftpProxy: kSecAttrProtocolFTPProxy
      case .smb: kSecAttrProtocolSMB
      case .rtsp: kSecAttrProtocolRTSP
      case .rtspProxy: kSecAttrProtocolRTSPProxy
      case .daap: kSecAttrProtocolDAAP
      case .eppc: kSecAttrProtocolEPPC
      case .ipp: kSecAttrProtocolIPP
      case .nntps: kSecAttrProtocolNNTPS
      case .ldaps: kSecAttrProtocolLDAPS
      case .telnetS: kSecAttrProtocolTelnetS
      case .imaps: kSecAttrProtocolIMAPS
      case .ircs: kSecAttrProtocolIRCS
      case .pop3S: kSecAttrProtocolPOP3S
      }
    }

    init?(value: Any?) {
      guard let value = keychainString(value) else { return nil }
      switch value {
      case String(kSecAttrProtocolFTP): self = .ftp
      case String(kSecAttrProtocolFTPAccount): self = .ftpAccount
      case String(kSecAttrProtocolHTTP): self = .http
      case String(kSecAttrProtocolIRC): self = .irc
      case String(kSecAttrProtocolNNTP): self = .nntp
      case String(kSecAttrProtocolPOP3): self = .pop3
      case String(kSecAttrProtocolSMTP): self = .smtp
      case String(kSecAttrProtocolSOCKS): self = .socks
      case String(kSecAttrProtocolIMAP): self = .imap
      case String(kSecAttrProtocolLDAP): self = .ldap
      case String(kSecAttrProtocolAppleTalk): self = .appleTalk
      case String(kSecAttrProtocolAFP): self = .afp
      case String(kSecAttrProtocolTelnet): self = .telnet
      case String(kSecAttrProtocolSSH): self = .ssh
      case String(kSecAttrProtocolFTPS): self = .ftps
      case String(kSecAttrProtocolHTTPS): self = .https
      case String(kSecAttrProtocolHTTPProxy): self = .httpProxy
      case String(kSecAttrProtocolHTTPSProxy): self = .httpsProxy
      case String(kSecAttrProtocolFTPProxy): self = .ftpProxy
      case String(kSecAttrProtocolSMB): self = .smb
      case String(kSecAttrProtocolRTSP): self = .rtsp
      case String(kSecAttrProtocolRTSPProxy): self = .rtspProxy
      case String(kSecAttrProtocolDAAP): self = .daap
      case String(kSecAttrProtocolEPPC): self = .eppc
      case String(kSecAttrProtocolIPP): self = .ipp
      case String(kSecAttrProtocolNNTPS): self = .nntps
      case String(kSecAttrProtocolLDAPS): self = .ldaps
      case String(kSecAttrProtocolTelnetS): self = .telnetS
      case String(kSecAttrProtocolIMAPS): self = .imaps
      case String(kSecAttrProtocolIRCS): self = .ircs
      case String(kSecAttrProtocolPOP3S): self = .pop3S
      default: return nil
      }
    }
  }

  /// Internet password authentication values used by `SecurityHandle.Keychain.Password.Attributes`.
  public enum AuthenticationType: Equatable {
    case ntlm, msn, dpa, rpa, httpBasic, httpDigest, htmlForm
    case `default`

    var value: CFString {
      switch self {
      case .ntlm: kSecAttrAuthenticationTypeNTLM
      case .msn: kSecAttrAuthenticationTypeMSN
      case .dpa: kSecAttrAuthenticationTypeDPA
      case .rpa: kSecAttrAuthenticationTypeRPA
      case .httpBasic: kSecAttrAuthenticationTypeHTTPBasic
      case .httpDigest: kSecAttrAuthenticationTypeHTTPDigest
      case .htmlForm: kSecAttrAuthenticationTypeHTMLForm
      case .default: kSecAttrAuthenticationTypeDefault
      }
    }

    init?(value: Any?) {
      guard let value = keychainString(value) else { return nil }
      switch value {
      case String(kSecAttrAuthenticationTypeNTLM): self = .ntlm
      case String(kSecAttrAuthenticationTypeMSN): self = .msn
      case String(kSecAttrAuthenticationTypeDPA): self = .dpa
      case String(kSecAttrAuthenticationTypeRPA): self = .rpa
      case String(kSecAttrAuthenticationTypeHTTPBasic): self = .httpBasic
      case String(kSecAttrAuthenticationTypeHTTPDigest): self = .httpDigest
      case String(kSecAttrAuthenticationTypeHTMLForm): self = .htmlForm
      case String(kSecAttrAuthenticationTypeDefault): self = .default
      default: return nil
      }
    }
  }
}
