import Foundation
import Security

/// Error values returned by Security.framework Keychain operations.
extension SecurityHandle {
public enum Error: LocalizedError, Equatable {
  case unimplemented
  case diskFull
  case io
  case fileAlreadyOpenWithWritePermission
  case parameter
  case writePermission
  case allocationFailed
  case userCanceled
  case badRequest
  case internalComponent
  case coreFoundationUnknown
  case missingEntitlement
  case restrictedAPI
  case notAvailable
  case readOnly
  case authenticationFailed
  case noSuchKeychain
  case invalidKeychain
  case duplicateKeychain
  case duplicateCallback
  case invalidCallback
  case duplicateItem
  case itemNotFound
  case bufferTooSmall
  case dataTooLarge
  case noSuchAttribute
  case invalidItemReference
  case invalidSearchReference
  case noSuchClass
  case noDefaultKeychain
  case interactionNotAllowed
  case readOnlyAttribute
  case wrongSecurityVersion
  case keySizeNotAllowed
  case noStorageModule
  case noCertificateModule
  case noPolicyModule
  case interactionRequired
  case dataNotAvailable
  case dataNotModifiable
  case createChainFailed
  case invalidPreferencesDomain
  case inDarkWake
  case accessControlListNotSimple
  case policyNotFound
  case invalidTrustSetting
  case noAccessForItem
  case invalidOwnerEdit
  case trustNotAvailable
  case unsupportedFormat
  case unknownFormat
  case keyIsSensitive
  case multiplePrivateKeys
  case passphraseRequired
  case invalidPasswordReference
  case invalidTrustSettings
  case noTrustSettings
  case pkcs12VerifyFailure
  case notSigner
  case decode
  case serviceNotAvailable
  case insufficientClientID
  case deviceReset
  case deviceFailed
  case quotaExceeded
  case fileTooBig
  case invalidDatabaseBlob
  case invalidKeyBlob
  case incompatibleDatabaseBlob
  case incompatibleKeyBlob
  case conversionError
  case unknown(OSStatus)

  public static func fromValue(_ status: OSStatus) -> SecurityHandle.Error? {
    switch status {
    case errSecSuccess: nil
    case errSecUnimplemented: .unimplemented
    case errSecDiskFull: .diskFull
    case errSecIO: .io
    case errSecOpWr: .fileAlreadyOpenWithWritePermission
    case errSecParam: .parameter
    case errSecWrPerm: .writePermission
    case errSecAllocate: .allocationFailed
    case errSecUserCanceled: .userCanceled
    case errSecBadReq: .badRequest
    case errSecInternalComponent: .internalComponent
    case errSecCoreFoundationUnknown: .coreFoundationUnknown
    case errSecMissingEntitlement: .missingEntitlement
    case errSecRestrictedAPI: .restrictedAPI
    case errSecNotAvailable: .notAvailable
    case errSecReadOnly: .readOnly
    case errSecAuthFailed: .authenticationFailed
    case errSecNoSuchKeychain: .noSuchKeychain
    case errSecInvalidKeychain: .invalidKeychain
    case errSecDuplicateKeychain: .duplicateKeychain
    case errSecDuplicateCallback: .duplicateCallback
    case errSecInvalidCallback: .invalidCallback
    case errSecDuplicateItem: .duplicateItem
    case errSecItemNotFound: .itemNotFound
    case errSecBufferTooSmall: .bufferTooSmall
    case errSecDataTooLarge: .dataTooLarge
    case errSecNoSuchAttr: .noSuchAttribute
    case errSecInvalidItemRef: .invalidItemReference
    case errSecInvalidSearchRef: .invalidSearchReference
    case errSecNoSuchClass: .noSuchClass
    case errSecNoDefaultKeychain: .noDefaultKeychain
    case errSecInteractionNotAllowed: .interactionNotAllowed
    case errSecReadOnlyAttr: .readOnlyAttribute
    case errSecWrongSecVersion: .wrongSecurityVersion
    case errSecKeySizeNotAllowed: .keySizeNotAllowed
    case errSecNoStorageModule: .noStorageModule
    case errSecNoCertificateModule: .noCertificateModule
    case errSecNoPolicyModule: .noPolicyModule
    case errSecInteractionRequired: .interactionRequired
    case errSecDataNotAvailable: .dataNotAvailable
    case errSecDataNotModifiable: .dataNotModifiable
    case errSecCreateChainFailed: .createChainFailed
    case errSecInvalidPrefsDomain: .invalidPreferencesDomain
    case errSecInDarkWake: .inDarkWake
    case errSecACLNotSimple: .accessControlListNotSimple
    case errSecPolicyNotFound: .policyNotFound
    case errSecInvalidTrustSetting: .invalidTrustSetting
    case errSecNoAccessForItem: .noAccessForItem
    case errSecInvalidOwnerEdit: .invalidOwnerEdit
    case errSecTrustNotAvailable: .trustNotAvailable
    case errSecUnsupportedFormat: .unsupportedFormat
    case errSecUnknownFormat: .unknownFormat
    case errSecKeyIsSensitive: .keyIsSensitive
    case errSecMultiplePrivKeys: .multiplePrivateKeys
    case errSecPassphraseRequired: .passphraseRequired
    case errSecInvalidPasswordRef: .invalidPasswordReference
    case errSecInvalidTrustSettings: .invalidTrustSettings
    case errSecNoTrustSettings: .noTrustSettings
    case errSecPkcs12VerifyFailure: .pkcs12VerifyFailure
    case errSecNotSigner: .notSigner
    case errSecDecode: .decode
    case errSecServiceNotAvailable: .serviceNotAvailable
    case errSecInsufficientClientID: .insufficientClientID
    case errSecDeviceReset: .deviceReset
    case errSecDeviceFailed: .deviceFailed
    case errSecQuotaExceeded: .quotaExceeded
    case errSecFileTooBig: .fileTooBig
    case errSecInvalidDatabaseBlob: .invalidDatabaseBlob
    case errSecInvalidKeyBlob: .invalidKeyBlob
    case errSecIncompatibleDatabaseBlob: .incompatibleDatabaseBlob
    case errSecIncompatibleKeyBlob: .incompatibleKeyBlob
    case errSecConversionError: .conversionError
    default: .unknown(status)
    }
  }

  public var errorDescription: String? {
    let status = statusValue
    return SecCopyErrorMessageString(status, nil) as String? ?? "Security framework error \(status)"
  }

  public var statusValue: OSStatus {
    switch self {
    case .unimplemented: errSecUnimplemented
    case .diskFull: errSecDiskFull
    case .io: errSecIO
    case .fileAlreadyOpenWithWritePermission: errSecOpWr
    case .parameter: errSecParam
    case .writePermission: errSecWrPerm
    case .allocationFailed: errSecAllocate
    case .userCanceled: errSecUserCanceled
    case .badRequest: errSecBadReq
    case .internalComponent: errSecInternalComponent
    case .coreFoundationUnknown: errSecCoreFoundationUnknown
    case .missingEntitlement: errSecMissingEntitlement
    case .restrictedAPI: errSecRestrictedAPI
    case .notAvailable: errSecNotAvailable
    case .readOnly: errSecReadOnly
    case .authenticationFailed: errSecAuthFailed
    case .noSuchKeychain: errSecNoSuchKeychain
    case .invalidKeychain: errSecInvalidKeychain
    case .duplicateKeychain: errSecDuplicateKeychain
    case .duplicateCallback: errSecDuplicateCallback
    case .invalidCallback: errSecInvalidCallback
    case .duplicateItem: errSecDuplicateItem
    case .itemNotFound: errSecItemNotFound
    case .bufferTooSmall: errSecBufferTooSmall
    case .dataTooLarge: errSecDataTooLarge
    case .noSuchAttribute: errSecNoSuchAttr
    case .invalidItemReference: errSecInvalidItemRef
    case .invalidSearchReference: errSecInvalidSearchRef
    case .noSuchClass: errSecNoSuchClass
    case .noDefaultKeychain: errSecNoDefaultKeychain
    case .interactionNotAllowed: errSecInteractionNotAllowed
    case .readOnlyAttribute: errSecReadOnlyAttr
    case .wrongSecurityVersion: errSecWrongSecVersion
    case .keySizeNotAllowed: errSecKeySizeNotAllowed
    case .noStorageModule: errSecNoStorageModule
    case .noCertificateModule: errSecNoCertificateModule
    case .noPolicyModule: errSecNoPolicyModule
    case .interactionRequired: errSecInteractionRequired
    case .dataNotAvailable: errSecDataNotAvailable
    case .dataNotModifiable: errSecDataNotModifiable
    case .createChainFailed: errSecCreateChainFailed
    case .invalidPreferencesDomain: errSecInvalidPrefsDomain
    case .inDarkWake: errSecInDarkWake
    case .accessControlListNotSimple: errSecACLNotSimple
    case .policyNotFound: errSecPolicyNotFound
    case .invalidTrustSetting: errSecInvalidTrustSetting
    case .noAccessForItem: errSecNoAccessForItem
    case .invalidOwnerEdit: errSecInvalidOwnerEdit
    case .trustNotAvailable: errSecTrustNotAvailable
    case .unsupportedFormat: errSecUnsupportedFormat
    case .unknownFormat: errSecUnknownFormat
    case .keyIsSensitive: errSecKeyIsSensitive
    case .multiplePrivateKeys: errSecMultiplePrivKeys
    case .passphraseRequired: errSecPassphraseRequired
    case .invalidPasswordReference: errSecInvalidPasswordRef
    case .invalidTrustSettings: errSecInvalidTrustSettings
    case .noTrustSettings: errSecNoTrustSettings
    case .pkcs12VerifyFailure: errSecPkcs12VerifyFailure
    case .notSigner: errSecNotSigner
    case .decode: errSecDecode
    case .serviceNotAvailable: errSecServiceNotAvailable
    case .insufficientClientID: errSecInsufficientClientID
    case .deviceReset: errSecDeviceReset
    case .deviceFailed: errSecDeviceFailed
    case .quotaExceeded: errSecQuotaExceeded
    case .fileTooBig: errSecFileTooBig
    case .invalidDatabaseBlob: errSecInvalidDatabaseBlob
    case .invalidKeyBlob: errSecInvalidKeyBlob
    case .incompatibleDatabaseBlob: errSecIncompatibleDatabaseBlob
    case .incompatibleKeyBlob: errSecIncompatibleKeyBlob
    case .conversionError: errSecConversionError
    case .unknown(let status): status
    }
  }
}
}
