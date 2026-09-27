#!/usr/bin/env bash
# Run the XCUITest journeys against the app on a simulator.
#
#   scripts/run_ios_ui_tests.sh [SIMULATOR-NAME-OR-UDID]
#
# The tests pick files through the system document picker, so the files have
# to be in the app's Documents folder before the tests start -- and the UI test
# runner cannot write into another app's container. So the app is built and
# installed first, the fixtures are copied in from the host, and only then are
# the tests run, without rebuilding (which would reinstall over them; installing
# over an existing app keeps its data container, so the fixtures survive).
set -euo pipefail

cd "$(dirname "$0")/.."
DEVICE="${1:-}"
if [ -z "$DEVICE" ]; then
  # An iPhone on the runtime that matches the SDK the app is built with.
  # Picking the newest installed runtime instead put an Xcode 16.4 build and
  # its XCTest in front of an iOS 26 system document picker on CI, where taps on
  # PDFs in the picker were dropped; the same tests pass when the two match.
  SDK="$(xcrun --sdk iphonesimulator --show-sdk-version)"
  DEVICE="$(xcrun simctl list devices available -j | "${PYTHON:-python3}" -c '
import json, sys

sdk = tuple(int(part) for part in sys.argv[1].split("."))

def version(runtime):
    # com.apple.CoreSimulator.SimRuntime.iOS-18-5 -> (18, 5)
    return tuple(int(part) for part in runtime.rsplit(".", 1)[-1].split("-")[1:])

candidates = []
for runtime, devices in json.load(sys.stdin)["devices"].items():
    if ".iOS-" not in runtime:
        continue
    for device in devices:
        if device["name"].startswith("iPhone"):
            candidates.append((version(runtime), device["udid"]))
if not candidates:
    raise SystemExit("no iPhone simulator is available")

# The exact SDK version if there is one; otherwise the newest runtime that is
# not newer than the SDK; otherwise, as a last resort, the oldest available.
exact = [c for c in candidates if c[0][:2] == sdk[:2]]
older = sorted(c for c in candidates if c[0] <= sdk)
chosen = exact[0] if exact else (older[-1] if older else sorted(candidates)[0])
print(chosen[1])
' "$SDK")"
  echo "==> iOS $SDK SDK; testing on simulator $DEVICE"
fi
DERIVED="${DERIVED_DATA:-build/ios-uitests}"
PYTHON="${PYTHON:-python3}"
BUNDLE_ID="dev.jayanth.filepasswordremover"

echo "==> booting $DEVICE"
xcrun simctl boot "$DEVICE" 2>/dev/null || true
xcrun simctl bootstatus "$DEVICE" -b >/dev/null

UDID="$(xcrun simctl list devices booted -j | "$PYTHON" -c '
import json, sys
wanted = sys.argv[1]
for runtime in json.load(sys.stdin)["devices"].values():
    for device in runtime:
        if device["state"] == "Booted" and wanted in (device["name"], device["udid"]):
            print(device["udid"]); raise SystemExit
raise SystemExit("simulator not booted: " + wanted)
' "$DEVICE")"
DESTINATION="platform=iOS Simulator,id=$UDID"

echo "==> building the app and its UI tests"
xcodebuild build-for-testing \
  -project ios/FilePasswordRemover.xcodeproj -scheme FilePasswordRemover \
  -destination "$DESTINATION" -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO -quiet

echo "==> installing, then putting the fixtures where the picker will find them"
xcrun simctl install "$UDID" "$DERIVED/Build/Products/Debug-iphonesimulator/FilePasswordRemover.app"
CONTAINER="$(xcrun simctl get_app_container "$UDID" "$BUNDLE_ID" data)"
mkdir -p "$CONTAINER/Documents"
"$PYTHON" - "$CONTAINER/Documents" <<'PYEOF'
import sys
from pathlib import Path

from fpr.testing import fixtures as F

documents = Path(sys.argv[1])
for stale in documents.iterdir():
    if stale.is_file():
        stale.unlink()
# The PDFs are written without an extension. With one, the picker asks Quick
# Look for a thumbnail before it hands the file over, and on a headless CI
# runner that render stalls: the cell takes taps and never returns the file
# (the ZIP, which only ever gets a generic icon, was unaffected). Without one
# there is nothing to preview -- and the app has to recognise these as PDFs by
# their content, which is how it identifies every file anyway.
(documents / "locked").write_bytes(
    F.make_pdf(F.PdfSpec(user=F.SAMPLE_PASSWORD, owner=F.OWNER_PASSWORD))
)
(documents / "plain").write_bytes(F.make_pdf())
(documents / "aes.zip").write_bytes(F.make_zip_aes())
print("   seeded:", ", ".join(sorted(p.name for p in documents.iterdir())))
PYEOF

echo "==> running the journeys"
# xcodebuild refuses to overwrite a result bundle from an earlier run.
rm -rf "$DERIVED/JourneyUITests.xcresult"
xcodebuild test-without-building \
  -project ios/FilePasswordRemover.xcodeproj -scheme FilePasswordRemover \
  -destination "$DESTINATION" -derivedDataPath "$DERIVED" \
  -resultBundlePath "$DERIVED/JourneyUITests.xcresult" \
  CODE_SIGNING_ALLOWED=NO
