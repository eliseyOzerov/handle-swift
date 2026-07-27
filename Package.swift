// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "Handle",
  platforms: [.iOS(.v18), .macOS(.v14), .tvOS(.v17), .visionOS(.v1)],
  products: [
    .library(name: "HandleSecurity", targets: ["HandleSecurity"]),
  ],
  targets: [
    .target(name: "HandleSecurity"),
    .testTarget(name: "HandleSecurityTests", dependencies: ["HandleSecurity"]),
  ]
)
