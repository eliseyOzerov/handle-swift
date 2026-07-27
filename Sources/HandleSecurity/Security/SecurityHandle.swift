/// Root namespace for HandleSecurity's Security.framework adapters.
public enum SecurityHandle {
  /// Keychain services for passwords, keys, certificates, identities, shared attributes, and match queries.
  public typealias Keychain = HandleSecurity.Keychain

  /// App-shaped handle for common generic password Keychain operations.
  public typealias KeychainHandle = HandleSecurity.KeychainHandle

  /// Stable identifier used by `KeychainHandle`.
  public typealias KeychainKey = HandleSecurity.KeychainKey

  /// Test handle for common generic password Keychain operations.
  public typealias TestKeychainHandle = HandleSecurity.TestKeychainHandle

  /// Security.framework result-code error mapping.
  public typealias Error = HandleSecurity.KeychainError
}
