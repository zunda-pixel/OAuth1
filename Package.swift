// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "OAuth1",
    platforms: [.macOS(.v10_15), .iOS(.v13), .watchOS(.v6), .tvOS(.v13), .macCatalyst(.v13)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "OAuth1",
            targets: ["OAuth1"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
      .package(url: "https://github.com/thii/HTTPMethod", .upToNextMajor(from: "0.1.0")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "OAuth1",
            dependencies: [
              .product(name: "HTTPMethod", package: "HTTPMethod")
            ]),
        .testTarget(
            name: "OAuth1Tests",
            dependencies: ["OAuth1"]),
    ]
)

#if os(Linux) || os(Windows)
  package.dependencies.append(.package(url: "https://github.com/apple/swift-crypto", .upToNextMajor(from: "2.0.0")))
  package.targets[0].dependencies.append(.product(name: "Crypto", package: "swift-crypto"))
#endif
