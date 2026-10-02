#!/usr/bin/env bash
# Usage: KOTLINC=... COMPILE_JAR=<android-all-12 jar> tools/jvm-smoke/run.sh [path/to/apk]
set -euo pipefail
cd "$(dirname "$0")"
OUT=$(mktemp -d)
STDLIB=$(dirname "$(readlink -f "$(command -v "${KOTLINC:-kotlinc}")")")/../lib/kotlin-stdlib.jar
mkdir -p "$OUT/shadow" "$OUT/classes"
javac -d "$OUT/shadow" $(find shadow -name '*.java')
"${KOTLINC:-kotlinc}" -jvm-target 1.8 -classpath "$COMPILE_JAR" -d "$OUT/classes" \
    $(find ../../app/src/main/java -name '*.kt') $(find fake -name '*.kt') SmokeTest.kt 2>&1 | grep -v '^warning' || true
java -cp "$OUT/shadow:$OUT/classes:$COMPILE_JAR:$STDLIB" SmokeTestKt "$@"
