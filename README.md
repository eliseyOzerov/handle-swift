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

It also includes a small app-shaped handle for common generic password use:

```swift
import HandleSecurity

let key = KeychainKey.service("wave-api", "accessToken")
try KeychainHandle.shared.set(token, for: key)

let token = try KeychainHandle.shared.string(for: key)
```

Tests can use a single test double that stubs behavior, records calls, and stores values in memory:

```swift
let keychain = TestKeychainHandle()
try keychain.set("token", for: .service("wave-api", "accessToken"))

XCTAssertEqual(try keychain.string(for: .service("wave-api", "accessToken")), "token")
XCTAssertEqual(keychain.setDataCallCount, 1)
```
