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

Get `7x-sr-probe-v0.1-debug.apk` from the [Releases](../../releases) page. SHA-256: `461ac978714cc29eaf541c9243bef6f13e198c1e353cc7f1205e699c4660ef8c`.

## Credits

Vehicle API names and signal ids come from public research by the [dts88/zeekr-shortcut-car](https://github.com/dts88/zeekr-shortcut-car) project (GPL-3.0). No code was copied from it.
