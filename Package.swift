// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "Handle",
  platforms: [.iOS(.v18), .macOS(.v14), .tvOS(.v17), .visionOS(.v1)],
  products: [
    .library(name: "HandleAuth", targets: ["HandleAuth"]),
    .library(name: "HandleSecurity", targets: ["HandleSecurity"]),
  ],
  targets: [
    .target(name: "HandleAuth", dependencies: ["HandleSecurity"]),
    .testTarget(name: "HandleAuthTests", dependencies: ["HandleAuth"]),
    .target(name: "HandleSecurity"),
    .testTarget(name: "HandleSecurityTests", dependencies: ["HandleSecurity"]),
  ]
)
