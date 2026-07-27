# Handle

Handle turns ceremony-heavy Apple framework APIs into small, direct Swift services with first-party test handles.

## Products

### HandleAuth

`HandleAuth` wraps Apple authentication APIs that are usually delegate- or context-heavy.

Sign in with Apple:

```swift
import HandleAuth

let result = try await AuthHandle.Apple.shared.signIn()

let apple = AuthHandle.Apple.Test()
apple.setSignInResult(.init(
  identityToken: "identity-token",
  userID: "user-id",
  nonce: "nonce",
  displayName: "Taylor"
))
```

Local authentication with biometry or passcode:

```swift
let local = AuthHandle.Local.shared

if local.canAuthenticate(policy: .deviceOwner).isAvailable {
  try await local.authenticate(reason: "Unlock private notes")
}

let testLocal = AuthHandle.Local.Test()
testLocal.setAuthenticationResult(.init(policy: .deviceOwner, biometryType: .faceID))
```

### HandleSecurity

`HandleSecurity` ports ForgeSecurity's Keychain coverage into a standalone package:

- generic and internet passwords
- certificates
- identities
- cryptographic keys
- shared Keychain attributes and match queries
- Security.framework status error mapping

The canonical namespace is `SecurityHandle`:

```swift
import HandleSecurity

let attributes = SecurityHandle.Keychain.Password.Attributes.service(
  "wave-api",
  label: "accessToken"
)

try SecurityHandle.Keychain.shared.save(token, for: attributes)
let token = try SecurityHandle.Keychain.shared.find(attributes)
```
