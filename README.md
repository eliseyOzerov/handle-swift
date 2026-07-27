# Handle

Handle turns ceremony-heavy Apple framework APIs into small, direct Swift services with first-party test handles.

## Products

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
