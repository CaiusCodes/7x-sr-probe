#!/usr/bin/env bash
# Usage: KOTLINC=... COMPILE_JAR=<android-all-12 jar> tools/jvm-smoke/run.sh [path/to/apk]
set -euo pipefail
cd "$(dirname "$0")"
OUT=$(mktemp -d)
STDLIB=$(dirname "$(readlink -f "$(command -v "${KOTLINC:-kotlinc}")")")/../lib/kotlin-stdlib.jar
TFLITE=../../third_party/tflite/tensorflow-lite-2.16.1.jar:../../third_party/tflite/tensorflow-lite-api-2.16.1.jar
mkdir -p "$OUT/shadow" "$OUT/classes"
javac -d "$OUT/shadow" $(find shadow -name '*.java')
"${KOTLINC:-kotlinc}" -jvm-target 1.8 -classpath "$COMPILE_JAR:$TFLITE" -d "$OUT/classes" \
    $(find ../../app/src/main/java -name '*.kt') $(find fake -name '*.kt') SmokeTest.kt 2>&1 | grep -v '^warning' || true
# A dexed stand-in "SRObject" so the v0.3 member parser has a vendor class to read.
EXTRA=()
DX=${DX:-/usr/lib/android-sdk/build-tools/debian/dx}
if [ $# -gt 0 ] && [ -x "$DX" ]; then
    mkdir -p "$OUT/sr"; javac -source 8 -target 8 -d "$OUT/sr" $(find fake-sr -name '*.java') 2>/dev/null
    "$DX" --dex --output="$OUT/sr.apk" "$OUT/sr" && EXTRA=("$OUT/sr.apk")
fi
java -cp "$OUT/shadow:$OUT/classes:$COMPILE_JAR:$STDLIB:$TFLITE" SmokeTestKt "$@" "${EXTRA[@]}"
