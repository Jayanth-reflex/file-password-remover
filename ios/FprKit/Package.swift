// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FprKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "FprKit", targets: ["FprKit"])
    ],
    targets: [
        .target(name: "FprKit"),
        .testTarget(name: "FprKitTests", dependencies: ["FprKit"]),
    ]
)
