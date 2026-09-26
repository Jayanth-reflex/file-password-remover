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
  # Whatever iPhone this Xcode ships a runtime for: runner images change the
  # set of simulators more often than this script changes.
  DEVICE="$(xcrun simctl list devices available -j | "${PYTHON:-python3}" -c '
import json, sys
for runtime, devices in sorted(json.load(sys.stdin)["devices"].items(), reverse=True):
    if "iOS" not in runtime:
        continue
    for device in devices:
        if device["name"].startswith("iPhone"):
            print(device["udid"]); raise SystemExit
raise SystemExit("no iPhone simulator is available")
')"
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
(documents / "locked.pdf").write_bytes(
    F.make_pdf(F.PdfSpec(user=F.SAMPLE_PASSWORD, owner=F.OWNER_PASSWORD))
)
(documents / "plain.pdf").write_bytes(F.make_pdf())
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
