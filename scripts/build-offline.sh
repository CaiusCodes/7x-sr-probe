#!/usr/bin/env bash
# Builds and signs the SR Probe debug APK WITHOUT Gradle or Google's SDK download host.
# Used to produce dist/7x-sr-probe-v0.8.5-debug.apk in an environment where dl.google.com was blocked.
# The normal route is Android Studio / Gradle (see docs/BUILD_AND_INSTALL.md); both build the same sources.
#
# Needs: JDK 17+, kotlinc 2.0.x, Debian/Ubuntu android-sdk-build-tools (aapt2, dx, zipalign, apksigner),
#        android-sdk-platform-23 (android.jar for resource linking), and an Android 12 framework jar for
#        compiling Kotlin (Robolectric org.robolectric:android-all:12-robolectric-7732740 from Maven Central).
#
# Env overrides: KOTLINC, BUILD_TOOLS, PLATFORM_JAR, COMPILE_JAR, KEYSTORE
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
KOTLINC=${KOTLINC:-kotlinc}
BUILD_TOOLS=${BUILD_TOOLS:-/usr/lib/android-sdk/build-tools/debian}
PLATFORM_JAR=${PLATFORM_JAR:-/usr/lib/android-sdk/platforms/android-23/android.jar}
COMPILE_JAR=${COMPILE_JAR:?set COMPILE_JAR to an Android 12 framework jar}
OUT=${OUT:-$ROOT/build-offline}
KEYSTORE=${KEYSTORE:-$HOME/.android/debug.keystore}
PKG=au.local.zeekr.srprobe
VERSION_CODE=16
VERSION_NAME=0.8.5

# On-device detection runtime (third_party/tflite, Apache-2.0).
TFLITE_JARS="$ROOT/third_party/tflite/tensorflow-lite-2.16.1.jar:$ROOT/third_party/tflite/tensorflow-lite-api-2.16.1.jar"

rm -rf "$OUT"; mkdir -p "$OUT/classes" "$OUT/res" "$OUT/dex"

# 1. Manifest: AGP injects package/version/sdk from build.gradle.kts; do the same here.
sed -e "s#<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">#<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"$PKG\" android:versionCode=\"$VERSION_CODE\" android:versionName=\"$VERSION_NAME\">\n    <uses-sdk android:minSdkVersion=\"26\" android:targetSdkVersion=\"34\" />#" \
    app/src/main/AndroidManifest.xml > "$OUT/AndroidManifest.xml"

# 2. Resources.
"$BUILD_TOOLS/aapt2" compile --dir app/src/main/res -o "$OUT/res/res.zip"
"$BUILD_TOOLS/aapt2" link -I "$PLATFORM_JAR" --manifest "$OUT/AndroidManifest.xml" \
    --min-sdk-version 26 --target-sdk-version 34 -o "$OUT/base.apk" "$OUT/res/res.zip"

# 3. Kotlin -> JVM 1.8 bytecode without invokedynamic (dx cannot read indy lambdas / string concat).
STDLIB=$(dirname "$(readlink -f "$(command -v "$KOTLINC")")")/../lib/kotlin-stdlib.jar
"$KOTLINC" -jvm-target 1.8 -Xlambdas=class -Xsam-conversions=class -Xstring-concat=inline -no-reflect \
    -classpath "$COMPILE_JAR:$TFLITE_JARS" -d "$OUT/classes" $(find app/src/main/java -name '*.kt')

# 3b. dx cannot desugar invokedynamic, and Android has no LambdaMetafactory, so a surviving indy call site
# crashes on the head unit (v0.1 shipped with kotlin.comparisons.compareBy(vararg), which is built on indy
# lambdas inside the Kotlin stdlib). Fail the build if app code has indy or calls a known indy-based helper.
if find "$OUT/classes" -name '*.class' -print0 | xargs -0 javap -c -p 2>/dev/null | grep -E 'invokedynamic|ComparisonsKt.compareBy|kotlin/streams/jdk8|kotlin/uuid' ; then
  echo "ERROR: invokedynamic-based code reachable from app classes; replace it (see comment)" >&2; exit 1
fi

# 4. Dex (app classes + Kotlin stdlib minus multi-release entries).
mkdir -p "$OUT/stdlib"; (cd "$OUT/stdlib" && unzip -q -o "$STDLIB" -x 'META-INF/*')
mkdir -p "$OUT/tflite"; for j in ${TFLITE_JARS//:/ }; do (cd "$OUT/tflite" && unzip -q -o "$j" -x 'META-INF/*'); done
"$BUILD_TOOLS/dx" --dex --min-sdk-version=26 --output="$OUT/dex/classes.dex" "$OUT/classes" "$OUT/stdlib" "$OUT/tflite"

# 5. Package, align, sign (debug key).
cp "$OUT/base.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q -j "$OUT/unsigned.apk" classes.dex)
mkdir -p "$OUT/native/lib/arm64-v8a" && cp third_party/tflite/jni/arm64-v8a/*.so "$OUT/native/lib/arm64-v8a/"
(cd "$OUT/native" && zip -q -0 -r "$OUT/unsigned.apk" lib)
if [ -d app/src/main/assets ]; then (cd app/src/main && zip -q -0 -r "$OUT/unsigned.apk" assets); fi
"$BUILD_TOOLS/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
if [ ! -f "$KEYSTORE" ]; then
  mkdir -p "$(dirname "$KEYSTORE")"
  keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android -alias androiddebugkey \
      -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null
fi
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias androiddebugkey --out "$OUT/7x-sr-probe-v${VERSION_NAME}-debug.apk" "$OUT/aligned.apk"
"$BUILD_TOOLS/apksigner" verify --print-certs "$OUT/7x-sr-probe-v${VERSION_NAME}-debug.apk"
echo "APK: $OUT/7x-sr-probe-v${VERSION_NAME}-debug.apk"
