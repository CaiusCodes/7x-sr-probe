# 7X SR Probe v0.1 — Architecture and assumptions

## What v0.1 is for

One question: **what factory vehicle and perception data can an ordinary sideloaded App Lab app read on the Australian Zeekr 7X?** v0.1 inventories, reads a fixed set of known values, optionally records changes while parked, and exports one report. It renders nothing and changes nothing.

## What the public references already tell us (set expectations)

From dts88/zeekr-shortcut-car (`docs/zeekr-platform-notes.md`, read 2026-10-02), observed on a right-hand-drive 7X of unstated market:

| Finding | Status there | Meaning for us |
|---|---|---|
| App Lab runs apps inside a VLite container (`com.vlite.sdk`); `Build.*` is spoofed as a Pixel 3a | Observed | `Build.MODEL` is useless; the probe reads `ro.build.display.id` (reported as `zeekr_dhu_sa8295_ovs-userdebug 12 …`) |
| Real platform: Zeekr DHU, Qualcomm SA8295, Android 12 | Observed | Same SoC family as many Zeekr cockpits; the instrument cluster is likely a separate OS/VM on that chip (inference) |
| Standard `android.car` properties | SecurityException in the container | Not used |
| `com.zeekr.coreservice` vehicle SDK | Refuses third-party apps | Listed only |
| ECARX adapt API `com.ecarx.xui.adaptapi.car.Car` | Works with no permissions | This is v0.1's vehicle path |
| Speed, gear, steering, pedals, indicators, doors, lamps, factory 360 state | Readable | v0.1 reads these as the "known signals" baseline |
| ADAS | Only feature **switches** (AEB, LKA, RCW on/off); FCW/LDW read 255; no ACC-active state; no hands-on; drive-pilot id reads 255 parked | No perception data was found on that path |
| Composite surround camera via Camera2 (1280×5140) | Observed | Later phase; v0.1 does not touch the camera |

So the honest prior is: **structured perception objects are probably not exposed through the adapt API.** v0.1 is built to confirm that on your car and to look for any other path (another SDK on the class path, a binder service, a scene/SR package, a cluster display) without calling anything unproven.

## Layout

```
app/src/main/java/au/local/zeekr/srprobe/
  safety/   ReadOnlyGuard       single gate for every vehicle call; allowlist + mutator-prefix refusal + ledger
  platform/ AndroidEnvironment  Build.*, real build id via getprop, displays, permissions, class paths, container hints
            PackageDiscovery    visible packages, relevance filter, components (names only)
            ServiceDiscovery    binder service names; opt-in AIDL interface names
            DexScanner          own dex parser: class names / identifier strings / native libs / render assets, no code loaded
  ecarx/    EcarxAvailability   presence (no init) + Car.create + three manager getters
            VehicleSignalReader the four proven getters; Availability mapping
            KnownSignals        the 28 ids read, with provenance and decoding
            EcarxReflection     inspection-only reflection, BFS through vendor types
            SensorDiscovery     catalogue of SDK-named ADAS ids; opt-in single read
            CaptureSession      change-based polling + callback subscription; logs unknown callbacks
            Reflect             lookup helpers (never invoke)
  logging/  EventRecorder       probe log + JSONL events (monotonic + wall clock, change-only)
            ReportExporter      srprobe-report.md, srprobe-discovery.json, srprobe-events.jsonl, zip
            ReportProvider      read-only share provider
  model/    Models, Terms       plain data; relevance terms from the brief; future SceneObject/DetectionSource
  ui/       MainActivity        programmatic dark UI, large targets
            DiagnosticsViewModel ordered steps on one worker thread
            ProbeApplication
tools/jvm-smoke/   fake ECARX API + test proving no mutator/unverified method or class initialiser runs
scripts/build-offline.sh   Gradle-free build used to make dist/ here
```

Design choices worth knowing:

- **No AndroidX, no dependencies** beyond the Kotlin stdlib. Every behaviour is visible in these sources, and the APK is under 1 MB.
- **Vehicle code is isolated** in `ecarx/` and gated by `safety/`. A future 7X Driver View can reuse `ecarx/` + `model/` as its data layer; the UI and discovery code stay in the probe.
- **Feature detection, not assumptions:** every lookup is by reflection and degrades to `API_NOT_PRESENT` / `PERMISSION_DENIED` / `ERROR` / `UNAVAILABLE` (placeholder value) instead of crashing.
- **Provenance from day one:** `model/Models.kt` already defines `SceneObject` with `trackId`, `source: DetectionSource`, `confidence`, `observedAtNanos`, `lastUpdatedAtNanos` and raw fields, and every capture event carries monotonic and wall-clock timestamps plus the raw value. Nothing uses `SceneObject` yet.
- **Discovery order:** environment → packages → services → vendor-jar name scan → ECARX connect → known signals → reflection (seeded with every class name in the ECARX jar plus everything reachable from the live manager objects) → system-APK name scan (slowest, last).

## Assumptions not yet confirmed on an Australian 7X

1. The Australian firmware has App Lab and lets you install a debug-signed APK through your existing method. (Unknown whether App Lab enforces signing or an allowlist.)
2. It runs the same DHU platform (SA8295, Android 12) and the same VLite container as the reference car.
3. `ecarx.adaptapi.impl.jar` is on BOOTCLASSPATH and `Car.create(context)` works without permissions in the AU build.
4. The 28 signal ids mean the same thing, with the same units (speed in m/s, steering in radians left-positive, gear codes 0x002002x0), on AU firmware. The reference car's market is unknown; it is right-hand drive like yours.
5. Door zone 0x1 is the driver's (right front) door on an RHD car.
6. The ADAS ids are settings switches; none of them is live object/target data.
7. Hidden-but-accessible framework methods (`ServiceManager.listServices`, `SystemProperties.get`) are reachable from the container. If not, the report says so.
8. `QUERY_ALL_PACKAGES` has any effect inside the container (it may show only the container's view).
9. The report can leave the car through at least one of: Downloads, a USB folder picked in the system picker, or the share sheet.
10. Inference only: the cluster's surround-vehicle scene is produced outside the Android guest (cluster OS/VM or ADAS domain controller) and may not be reachable from App Lab at all.

## What the report will answer (brief §24)

1. Platform actually exposed: environment, real build id, container hints, displays.
2. Visible Zeekr/ECARX packages: "Relevant packages".
3. ECARX/Zeekr classes and read APIs: "ECARX API", "Relevant discovered classes".
4. Basic vehicle state: "Known vehicle signals".
5. ADAS/perception classes and event sources: "Candidate perception APIs", "Unknown event sources".
6. Zeekr Vision / SR component: "Zeekr Vision / SR indicators" (package names, render engine libs such as Unity/Kanzi/Unreal, scene assets).
7. What v0.2 should investigate: decided together from the above.
