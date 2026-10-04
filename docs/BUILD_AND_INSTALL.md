# Build and install — 7X SR Probe v0.1

## Option 1: use the prebuilt debug APK

`dist/7x-sr-probe-v0.9.1-debug.apk`
SHA-256 `d4c0e20432ec95843d7464d1861ad98681ec5fd7a877ee68550355e857200d3d`
Package `au.local.zeekr.srprobe`, version 0.4 (7), minSdk 26, targetSdk 34, signed with a throwaway Android debug key.

How it was built: Google's SDK and Maven hosts were blocked in the build environment, so it was built with `scripts/build-offline.sh` (Ubuntu's android-sdk-build-tools 29 for aapt2/dx/zipalign/apksigner, kotlinc 2.0.21, and the Android 12 framework jar from Maven Central for compiling). `tools/jvm-smoke` passed against that build. **It has not been run on an Android device or emulator**, so the first launch on the car is its first real run. The Gradle project below was not built here for the same network reason.

## Option 2: build it yourself (recommended if you want to audit the binary)

Requirements: Android Studio (Koala or newer) or JDK 17 + Android SDK with platform 34.

```
cd srprobe
./gradlew :app:assembleDebug        # Windows: gradlew.bat :app:assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Or open the `srprobe` folder in Android Studio and use Build › Build APK(s).

Before building, you can re-run the safety smoke test on any machine with a JDK and kotlinc:
```
KOTLINC=kotlinc COMPILE_JAR=/path/to/android-all-12-robolectric-7732740.jar tools/jvm-smoke/run.sh [path/to/apk]
```

If App Lab rejects debug-signed APKs, make a release build with your own key (Build › Generate Signed APK in Android Studio). Keep that key; later versions must be signed with the same one to update in place.

## Install on the car

Use the same App Lab / sideload method you already use. This app needs nothing special:

- **Permissions:** it requests only `QUERY_ALL_PACKAGES`. If the installer shows anything else, stop.
- **No runtime permission prompts** appear. If one does, deny it and note it.
- It does not need network, camera, location or storage permission. Export uses the system file picker or MediaStore.

If you have ADB access (unlikely on a production head unit), `adb install dist/7x-sr-probe-v0.9.1-debug.apk` also works. Do not enable developer options or ADB on the car just for this.

## Uninstall

Remove "7X SR Probe" the same way as any App Lab app. It stores nothing outside its own data folder except files you explicitly exported to `Download/SRProbe` or a folder you chose.
