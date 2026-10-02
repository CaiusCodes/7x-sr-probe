# 7X SR Probe v0.1

Read-only diagnostic app for an Australian-market Zeekr 7X. It answers one question: what factory vehicle and perception data can an ordinary sideloaded App Lab app read? It renders no visualisation and changes nothing on the car.

| File | What it is |
|---|---|
| GitHub Releases | Debug APK, ready to sideload |
| `READ_ONLY_AUDIT.md` | Every method the app invokes and why it is read-only; what it never calls |
| `docs/ARCHITECTURE.md` | Structure, public-reference findings, unconfirmed assumptions |
| `docs/BUILD_AND_INSTALL.md` | Build from source, install, uninstall |
| `docs/PARKED_TEST_PROCEDURE.md` | First test, entirely parked |
| `app/` | Kotlin source (package `au.local.zeekr.srprobe`) |
| `tools/jvm-smoke/` | Safety smoke test against a fake ECARX API |
| `scripts/build-offline.sh` | Gradle-free build used to produce `dist/` |

## Download

Get `7x-sr-probe-v0.3-debug.apk` from the [Releases](../../releases) page. SHA-256: `9a27c4e7aa41372c583954bb2f75c0ddf36d98f3ba79dde3ae3d9cd9196448bb`.

## Credits

Vehicle API names and signal ids come from public research by the [dts88/zeekr-shortcut-car](https://github.com/dts88/zeekr-shortcut-car) project (GPL-3.0). No code was copied from it.

## Changelog

- **0.3** v0.2 on the car found "SR objects" (perception fusion objects from the driving computer) in ZeekrVehicleService, ZeekrCarLauncherScene3D, CarControlMultiDisplay and XCLauncher3. v0.3 reads those apps' class members and manifests as bytes, to show what an SR object contains and which service, permission and action hand it out. Still names only; nothing is bound or called.
- **0.2** Deeper names-only search for surrounding-car data. App Lab hides most packages, so discovery now lists the system app folders directly and reads class names, vendor interface names, intent actions and manifest strings from every APK there (or its `.vdex` when the APK is stripped). It also lists config file names in `etc` folders. The summary leads with ranked perception-like names. No new vehicle calls; see READ_ONLY_AUDIT.md section B.
- **0.1.3** Adds **Show Summary (to photograph)**: a few full-screen pages of the key findings, for cars where no export route works. Display only; nothing is written or sent.
- **0.1.2** Adds **Copy Report To Clipboard (in parts)** for cars where USB/file export doesn't work. It only copies text to the clipboard; the app still has no network permission.
- **0.1.1** Fixes the "Reflect vendor classes" step crashing on the car (`BootstrapMethodError`). The build had left an invokedynamic call site in a Kotlin stdlib helper that Android cannot link. The helper is gone and `scripts/build-offline.sh` now fails if one reappears. Same signing key, so it installs over 0.1.
- **0.1** First release.
