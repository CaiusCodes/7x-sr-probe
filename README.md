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

Get `7x-sr-probe-v0.1.1-debug.apk` from the [Releases](../../releases) page. SHA-256: `64a345abb145e59e083b44e219dd2b1bd374307fde91af694c9dad8ec7ba5cef`.

## Credits

Vehicle API names and signal ids come from public research by the [dts88/zeekr-shortcut-car](https://github.com/dts88/zeekr-shortcut-car) project (GPL-3.0). No code was copied from it.

## Changelog

- **0.1.1** Fixes the "Reflect vendor classes" step crashing on the car (`BootstrapMethodError`). The build had left an invokedynamic call site in a Kotlin stdlib helper that Android cannot link. The helper is gone and `scripts/build-offline.sh` now fails if one reappears. Same signing key, so it installs over 0.1.
- **0.1** First release.
