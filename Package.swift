// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "Handle",
  platforms: [.iOS(.v18), .macOS(.v14), .tvOS(.v17), .visionOS(.v1)],
  products: [
    .library(name: "HandleAuth", targets: ["HandleAuth"]),
    .library(name: "HandleLocation", targets: ["HandleLocation"]),
    .library(name: "HandleSecurity", targets: ["HandleSecurity"]),
  ],
  dependencies: [
    .package(url: "https://github.com/Kolos65/Mockable", from: "0.6.4"),
  ],
  targets: [
    .target(
      name: "HandleAuth",
      dependencies: [
        "HandleSecurity",
        .product(name: "Mockable", package: "Mockable"),
      ],
      swiftSettings: [.define("MOCKING", .when(configuration: .debug))]
    ),
    .testTarget(
      name: "HandleAuthTests",
      dependencies: [
        "HandleAuth",
        .product(name: "Mockable", package: "Mockable"),
      ]
    ),
    .target(
      name: "HandleLocation",
      dependencies: [.product(name: "Mockable", package: "Mockable")],
      swiftSettings: [.define("MOCKING", .when(configuration: .debug))]
    ),
    .testTarget(
      name: "HandleLocationTests",
      dependencies: [
        "HandleLocation",
        .product(name: "Mockable", package: "Mockable"),
      ]
    ),
    .target(
      name: "HandleSecurity",
      dependencies: [.product(name: "Mockable", package: "Mockable")],
      swiftSettings: [.define("MOCKING", .when(configuration: .debug))]
    ),
    .testTarget(
      name: "HandleSecurityTests",
      dependencies: [
        "HandleSecurity",
        .product(name: "Mockable", package: "Mockable"),
      ]
    ),
  ]
)
