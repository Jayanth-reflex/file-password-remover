#!/usr/bin/env python3
"""Generate ios/FilePasswordRemover.xcodeproj.

XcodeGen would normally do this, but it installs through Homebrew and this
build host's Homebrew refuses to load formulae while an untrusted tap is
configured. The project is small and entirely mechanical, so it is generated
here instead of being committed as a large opaque file that nobody reviews.

Object IDs are derived from a hash of each object's role, so regenerating
produces a byte-identical project and diffs stay readable.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IOS = ROOT / "ios"
PROJECT = IOS / "FilePasswordRemover.xcodeproj"

BUNDLE_ID = "dev.jayanth.filepasswordremover"
DEPLOYMENT_TARGET = "17.0"
MARKETING_VERSION = "1.0.0"


def oid(role: str) -> str:
    return hashlib.sha256(role.encode()).hexdigest()[:24].upper()


def sources() -> list[tuple[str, Path]]:
    """App sources plus the engine, compiled straight into the app target.

    The engine is also a SwiftPM package (ios/FprKit) which is where its tests
    live; referencing the same files here keeps one source of truth rather than
    vendoring a copy.
    """
    files: list[tuple[str, Path]] = []
    for path in sorted((IOS / "App").glob("*.swift")):
        files.append((f"App/{path.name}", path))
    for path in sorted((IOS / "FprKit/Sources/FprKit").glob("*.swift")):
        files.append((f"FprKit/Sources/FprKit/{path.name}", path))
    return files


def build_settings(configuration: str) -> dict[str, str]:
    settings = {
        "ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS": "YES",
        "CLANG_ENABLE_MODULES": "YES",
        "CODE_SIGN_STYLE": "Automatic",
        "CURRENT_PROJECT_VERSION": "1",
        "ENABLE_PREVIEWS": "YES",
        "GENERATE_INFOPLIST_FILE": "NO",
        "INFOPLIST_FILE": "App/Info.plist",
        # Everything Info.plist-related lives in App/Info.plist, which is
        # explicit and reviewable; INFOPLIST_KEY_* settings silently drop keys
        # Xcode does not recognise.
        "IPHONEOS_DEPLOYMENT_TARGET": DEPLOYMENT_TARGET,
        "MARKETING_VERSION": MARKETING_VERSION,
        "PRODUCT_BUNDLE_IDENTIFIER": BUNDLE_ID,
        "PRODUCT_NAME": "$(TARGET_NAME)",
        "SDKROOT": "iphoneos",
        "SUPPORTED_PLATFORMS": "iphoneos iphonesimulator",
        "SWIFT_EMIT_LOC_STRINGS": "YES",
        "SWIFT_VERSION": "5.0",
        "TARGETED_DEVICE_FAMILY": "1,2",
    }
    if configuration == "Debug":
        settings |= {
            "DEBUG_INFORMATION_FORMAT": "dwarf",
            "ENABLE_TESTABILITY": "YES",
            "GCC_OPTIMIZATION_LEVEL": "0",
            "ONLY_ACTIVE_ARCH": "YES",
            "SWIFT_ACTIVE_COMPILATION_CONDITIONS": "DEBUG",
            "SWIFT_OPTIMIZATION_LEVEL": "-Onone",
        }
    else:
        settings |= {
            "DEBUG_INFORMATION_FORMAT": "dwarf-with-dsym",
            "SWIFT_COMPILATION_MODE": "wholemodule",
            "VALIDATE_PRODUCT": "YES",
        }
    return settings


# "$", "(", ")" and "-" must be quoted: an unquoted "(" opens an array.
_BARE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./")


def quote(value: str) -> str:
    """Old-style plist quoting: anything but a bare token needs quotes."""
    if value.startswith('"') and value.endswith('"'):
        return value
    if value and all(character in _BARE for character in value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_settings(settings: dict[str, str], indent: str) -> str:
    return "\n".join(
        f"{indent}{key} = {quote(value)};" for key, value in sorted(settings.items())
    )


def main() -> int:
    files = sources()
    target_id = oid("target/app")
    product_id = oid("product/app")
    group_root = oid("group/root")
    group_app = oid("group/app")
    group_kit = oid("group/kit")
    group_products = oid("group/products")
    sources_phase = oid("phase/sources")
    frameworks_phase = oid("phase/frameworks")
    resources_phase = oid("phase/resources")
    project_id = oid("project")
    config_list_project = oid("configlist/project")
    config_list_target = oid("configlist/target")

    lines: list[str] = []
    add = lines.append
    add("// !$*UTF8*$!")
    add("{")
    add("\tarchiveVersion = 1;")
    add("\tclasses = {")
    add("\t};")
    add("\tobjectVersion = 56;")
    add("\tobjects = {")

    # PBXBuildFile / PBXFileReference
    add("\n/* Begin PBXBuildFile section */")
    for relative, _ in files:
        add(
            f"\t\t{oid('buildfile/' + relative)} /* {Path(relative).name} in Sources */ = "
            f"{{isa = PBXBuildFile; fileRef = {oid('fileref/' + relative)} /* {Path(relative).name} */; }};"
        )
    add("/* End PBXBuildFile section */")

    add("\n/* Begin PBXFileReference section */")
    for relative, path in files:
        add(
            f"\t\t{oid('fileref/' + relative)} /* {Path(relative).name} */ = "
            f"{{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; "
            f'name = {Path(relative).name}; path = "{path.relative_to(IOS)}"; '
            f"sourceTree = \"<group>\"; }};"
        )
    add(
        f"\t\t{product_id} /* FilePasswordRemover.app */ = {{isa = PBXFileReference; "
        "explicitFileType = wrapper.application; includeInIndex = 0; "
        "path = FilePasswordRemover.app; sourceTree = BUILT_PRODUCTS_DIR; };"
    )
    add("/* End PBXFileReference section */")

    add("\n/* Begin PBXFrameworksBuildPhase section */")
    add(f"\t\t{frameworks_phase} = {{")
    add("\t\t\tisa = PBXFrameworksBuildPhase;")
    add("\t\t\tbuildActionMask = 2147483647;")
    add("\t\t\tfiles = (")
    add("\t\t\t);")
    add("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    add("\t\t};")
    add("/* End PBXFrameworksBuildPhase section */")

    add("\n/* Begin PBXGroup section */")
    add(f"\t\t{group_root} = {{")
    add("\t\t\tisa = PBXGroup;")
    add("\t\t\tchildren = (")
    add(f"\t\t\t\t{group_app} /* App */,")
    add(f"\t\t\t\t{group_kit} /* FprKit */,")
    add(f"\t\t\t\t{group_products} /* Products */,")
    add("\t\t\t);")
    add("\t\t\tsourceTree = \"<group>\";")
    add("\t\t};")
    for group_id, label, prefix in (
        (group_app, "App", "App/"),
        (group_kit, "FprKit", "FprKit/"),
    ):
        add(f"\t\t{group_id} /* {label} */ = {{")
        add("\t\t\tisa = PBXGroup;")
        add("\t\t\tchildren = (")
        for relative, _ in files:
            if relative.startswith(prefix):
                add(f"\t\t\t\t{oid('fileref/' + relative)} /* {Path(relative).name} */,")
        add("\t\t\t);")
        add(f"\t\t\tname = {label};")
        add("\t\t\tsourceTree = \"<group>\";")
        add("\t\t};")
    add(f"\t\t{group_products} /* Products */ = {{")
    add("\t\t\tisa = PBXGroup;")
    add("\t\t\tchildren = (")
    add(f"\t\t\t\t{product_id} /* FilePasswordRemover.app */,")
    add("\t\t\t);")
    add("\t\t\tname = Products;")
    add("\t\t\tsourceTree = \"<group>\";")
    add("\t\t};")
    add("/* End PBXGroup section */")

    add("\n/* Begin PBXNativeTarget section */")
    add(f"\t\t{target_id} /* FilePasswordRemover */ = {{")
    add("\t\t\tisa = PBXNativeTarget;")
    add(f"\t\t\tbuildConfigurationList = {config_list_target};")
    add("\t\t\tbuildPhases = (")
    add(f"\t\t\t\t{sources_phase},")
    add(f"\t\t\t\t{frameworks_phase},")
    add(f"\t\t\t\t{resources_phase},")
    add("\t\t\t);")
    add("\t\t\tbuildRules = (")
    add("\t\t\t);")
    add("\t\t\tdependencies = (")
    add("\t\t\t);")
    add("\t\t\tname = FilePasswordRemover;")
    add("\t\t\tproductName = FilePasswordRemover;")
    add(f"\t\t\tproductReference = {product_id} /* FilePasswordRemover.app */;")
    add("\t\t\tproductType = \"com.apple.product-type.application\";")
    add("\t\t};")
    add("/* End PBXNativeTarget section */")

    add("\n/* Begin PBXProject section */")
    add(f"\t\t{project_id} /* Project object */ = {{")
    add("\t\t\tisa = PBXProject;")
    add("\t\t\tattributes = {")
    add("\t\t\t\tBuildIndependentTargetsInParallel = 1;")
    add("\t\t\t\tLastSwiftUpdateCheck = 1600;")
    add("\t\t\t\tLastUpgradeCheck = 1600;")
    add("\t\t\t\tTargetAttributes = {")
    add(f"\t\t\t\t\t{target_id} = {{")
    add("\t\t\t\t\t\tCreatedOnToolsVersion = 16.0;")
    add("\t\t\t\t\t};")
    add("\t\t\t\t};")
    add("\t\t\t};")
    add(f"\t\t\tbuildConfigurationList = {config_list_project};")
    add("\t\t\tcompatibilityVersion = \"Xcode 14.0\";")
    add("\t\t\tdevelopmentRegion = en;")
    add("\t\t\thasScannedForEncodings = 0;")
    add("\t\t\tknownRegions = (")
    add("\t\t\t\ten,")
    add("\t\t\t\tBase,")
    add("\t\t\t);")
    add(f"\t\t\tmainGroup = {group_root};")
    add(f"\t\t\tproductRefGroup = {group_products} /* Products */;")
    add("\t\t\tprojectDirPath = \"\";")
    add("\t\t\tprojectRoot = \"\";")
    add("\t\t\ttargets = (")
    add(f"\t\t\t\t{target_id} /* FilePasswordRemover */,")
    add("\t\t\t);")
    add("\t\t};")
    add("/* End PBXProject section */")

    add("\n/* Begin PBXResourcesBuildPhase section */")
    add(f"\t\t{resources_phase} = {{")
    add("\t\t\tisa = PBXResourcesBuildPhase;")
    add("\t\t\tbuildActionMask = 2147483647;")
    add("\t\t\tfiles = (")
    add("\t\t\t);")
    add("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    add("\t\t};")
    add("/* End PBXResourcesBuildPhase section */")

    add("\n/* Begin PBXSourcesBuildPhase section */")
    add(f"\t\t{sources_phase} = {{")
    add("\t\t\tisa = PBXSourcesBuildPhase;")
    add("\t\t\tbuildActionMask = 2147483647;")
    add("\t\t\tfiles = (")
    for relative, _ in files:
        add(f"\t\t\t\t{oid('buildfile/' + relative)} /* {Path(relative).name} in Sources */,")
    add("\t\t\t);")
    add("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    add("\t\t};")
    add("/* End PBXSourcesBuildPhase section */")

    add("\n/* Begin XCBuildConfiguration section */")
    for scope in ("project", "target"):
        for configuration in ("Debug", "Release"):
            add(f"\t\t{oid(f'config/{scope}/{configuration}')} /* {configuration} */ = {{")
            add("\t\t\tisa = XCBuildConfiguration;")
            add("\t\t\tbuildSettings = {")
            add(render_settings(build_settings(configuration), "\t\t\t\t"))
            add("\t\t\t};")
            add(f"\t\t\tname = {configuration};")
            add("\t\t};")
    add("/* End XCBuildConfiguration section */")

    add("\n/* Begin XCConfigurationList section */")
    for scope, list_id in (("project", config_list_project), ("target", config_list_target)):
        add(f"\t\t{list_id} = {{")
        add("\t\t\tisa = XCConfigurationList;")
        add("\t\t\tbuildConfigurations = (")
        add(f"\t\t\t\t{oid(f'config/{scope}/Debug')} /* Debug */,")
        add(f"\t\t\t\t{oid(f'config/{scope}/Release')} /* Release */,")
        add("\t\t\t);")
        add("\t\t\tdefaultConfigurationIsVisible = 0;")
        add("\t\t\tdefaultConfigurationName = Release;")
        add("\t\t};")
    add("/* End XCConfigurationList section */")

    add("\t};")
    add(f"\trootObject = {project_id} /* Project object */;")
    add("}")

    PROJECT.mkdir(parents=True, exist_ok=True)
    (PROJECT / "project.pbxproj").write_text("\n".join(lines) + "\n")
    print(f"wrote {PROJECT} with {len(files)} source files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
