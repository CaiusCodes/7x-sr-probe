#!/usr/bin/env bash
# Builds and signs the SR Probe debug APK WITHOUT Gradle or Google's SDK download host.
# Used to produce dist/7x-sr-probe-v0.1-debug.apk in an environment where dl.google.com was blocked.
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
VERSION_CODE=1
VERSION_NAME=0.1

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
    -classpath "$COMPILE_JAR" -d "$OUT/classes" $(find app/src/main/java -name '*.kt')

# 4. Dex (app classes + Kotlin stdlib minus multi-release entries).
mkdir -p "$OUT/stdlib"; (cd "$OUT/stdlib" && unzip -q -o "$STDLIB" -x 'META-INF/*')
"$BUILD_TOOLS/dx" --dex --min-sdk-version=26 --output="$OUT/dex/classes.dex" "$OUT/classes" "$OUT/stdlib"

# 5. Package, align, sign (debug key).
cp "$OUT/base.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q -j "$OUT/unsigned.apk" classes.dex)
"$BUILD_TOOLS/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
if [ ! -f "$KEYSTORE" ]; then
  mkdir -p "$(dirname "$KEYSTORE")"
  keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android -alias androiddebugkey \
      -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null
fi
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias androiddebugkey --out "$OUT/7x-sr-probe-v0.1-debug.apk" "$OUT/aligned.apk"
"$BUILD_TOOLS/apksigner" verify --print-certs "$OUT/7x-sr-probe-v0.1-debug.apk"
echo "APK: $OUT/7x-sr-probe-v0.1-debug.apk"
