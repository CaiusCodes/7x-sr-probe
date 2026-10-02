# READ_ONLY_AUDIT.md — 7X SR Probe v0.1

This file lists every vehicle-specific and platform method the app invokes, why each is believed to be read-only, and what the app deliberately does **not** call. It was written against the source in `app/src/main/java` and must be updated before any new invocation is added.

## How the code enforces this

- **Every ECARX call** goes through `safety/ReadOnlyGuard.invoke()`. It holds an exact allowlist of method names *and* parameter shapes (section A). Anything else throws `ReadOnlyViolation` without being invoked. A second check refuses any name that starts with a mutating verb (`set`, `send`, `start`, `write`, `request`, `control`, …), even if someone later adds it to the list by mistake.
- **Framework calls made by reflection** (`ServiceManager`, `SystemProperties`) go through `ReadOnlyGuard.invokeFramework()`, which has its own three-entry allowlist (section B).
- **Every call site** that touches the vehicle API carries a `// VEHICLE CALL:` comment. `grep -rn "VEHICLE CALL" app/src` lists them all.
- **Run-time ledger:** the guard counts every invocation. The exported report starts with that ledger ("Read-only invocation ledger"), so you can check the real run against this file.
- **JVM smoke test** (`tools/jvm-smoke`): runs the ECARX layer against a fake adapt API that includes setters, an unverified `getPerceptionManager()`, `isFunctionSupported()`, `getCarInfoString()` and a class with a side-effecting static initialiser. The test fails if any of those runs. It passed on the build in `dist/`.

## Evidence used

The ECARX method names, shapes and signal ids come from the public project **dts88/zeekr-shortcut-car** (`docs/zeekr-platform-notes.md` and `app/src/main/java/com/kooo/evcam/telemetry/EcarxSource.java` / `Signal.java`, read 2026-10-02). That project reports these calls running on a right-hand-drive **Zeekr 7X in App Lab** (2026-09-28 onwards), with no permissions, in a shipping app. The car's market is not stated (the project is written in Chinese). **None of this has been observed on the Australian 7X.** No code was copied from that GPL-3.0 project; only facts (names, ids, units) are used, with attribution.

---

## A. ECARX adapt-API invocations (vehicle-specific)

### A1. Presence check
```
Method:              Class.forName("com.ecarx.xui.adaptapi.car.Car", initialize = false, loader)
Purpose:             Detect whether the ECARX adapt API is on this head unit's class path.
Why read-only:       initialize=false loads the class definition without running any static initialiser. No ECARX code runs.
Return type:         Class<?>
Known side effects:  None outside this process.
Source/reference:    EcarxAvailability.classPresent(), AndroidEnvironment.containerHints()
```

### A2. `Car.create(Context)` (static)
```
Method:              com.ecarx.xui.adaptapi.car.Car.create(android.content.Context)
Purpose:             Obtain the Car facade, the only entry point to the managers below.
Why read-only:       Factory method. It creates a client-side object and connects it to the ECARX car service; it takes no
                     vehicle parameters. Used by shortcut-car on every start in a shipping App Lab app on a 7X.
Return type:         Car (object)
Known side effects:  Opens a binder client connection from this process to the car service (~1 s on the reference car).
                     Called once per process (idempotent in EcarxAvailability.connect).
Source/reference:    EcarxAvailability.kt:71; shortcut-car EcarxSource.connect()
```

### A3–A5. Manager getters
```
Method:              Car.getICarFunction() / Car.getSensorManager() / Car.getCarInfoManager()
Purpose:             Obtain the function-value, sensor and static car-info managers.
Why read-only:       No-argument getters returning manager objects. Proven in shortcut-car EcarxSource.connect()/readDriverSide().
Return type:         ICarFunction / ISensor / ICarInfo implementations (exact interface names recorded in the report)
Known side effects:  None known.
Source/reference:    EcarxAvailability.kt:87-91
```
Any **other** getter on `Car` (for example a hypothetical `getXxxManager()`) is listed in the report and **not** called.

### A6. `ICarFunction.getFunctionValue(int id)`
```
Purpose:             Read one vehicle function value (lamp, door, gear-related, ADAS switch state).
Why read-only:       Getter: takes an id, returns the value the car service holds. Pairs with a separate setFunctionValue that
                     this app never calls. Called 0.2-0.9 ms per read on the reference car without effect.
Return type:         int (placeholders 255/254/253/-1/-65535 mean "no data")
Known side effects:  None known.
Ids passed:          Only the KnownSignal table (ecarx/KnownSignals.kt), the opt-in SDK-named ids (A12), never computed ranges.
Source/reference:    VehicleSignalReader.kt:28
```

### A7. `ICarFunction.getFunctionValue(int id, int zone)`
```
Purpose:             Same as A6 for zoned values. Used only for doors: id 0x21020100, zones 0x1 and 0x4.
Why read-only:       As A6. No zone sweep is performed.
Return type:         int
Known side effects:  None known.
Source/reference:    VehicleSignalReader.kt:28
```

### A8. `ISensor.getSensorEvent(int type)`
```
Purpose:             Read an enumerated sensor state (gear 0x00200200, day/night 0x00201000).
Why read-only:       Getter returning the latest cached event value.
Return type:         int
Known side effects:  None known.
Source/reference:    VehicleSignalReader.kt:28
```

### A9. `ISensor.getSensorLatestValue(int type)`
```
Purpose:             Read a float sensor (speed 0x00100100 m/s, steering 0x00101000 rad, brake 0x00101300, accelerator 0x00101400).
Why read-only:       Getter returning the latest cached sample.
Return type:         float
Known side effects:  None known.
Source/reference:    VehicleSignalReader.kt:28
```

### A10. `ICarInfo.getCarInfoInt(int id)`
```
Purpose:             Read which side the driver sits (id 0x00100300 only).
Why read-only:       Getter for static vehicle configuration.
Return type:         int (0x00100301 left, 0x00100302 right)
Known side effects:  None known.
Note:                getCarInfoString() is deliberately NOT called: it can return identifiers such as the VIN.
Source/reference:    VehicleSignalReader.kt:28; shortcut-car EcarxSource.readDriverSide()
```

### A11. Capture subscriptions (only after you press Start Read-Only Capture)
```
Method:              ICarFunction.registerFunctionValueWatcher(int[] ids, listener)  (or the (int, listener) per-id form)
                     ICarFunction.unregisterFunctionValueWatcher(listener)            (or the (int[]/int, listener) forms)
                     ISensor.registerListener(listener, int type)
Purpose:             Be told when known values change instead of only polling.
Why read-only:       They register a callback in the car service's listener list so it can deliver values to this app. They
                     carry no vehicle parameter other than which ids to watch. Same calls shortcut-car makes in its shipping app.
Return type:         boolean / void
Known side effects:  The car service keeps a reference to our listener. Reference project observation: sensor listeners
                     appear not to unregister cleanly, so they are registered once per process and ignored after Stop; the
                     registration ends when the app process dies. Function watchers are unregistered on Stop.
Ids passed:          KnownSignal function ids and the two KnownSignal sensor-event types (gear, day/night).
Source/reference:    CaptureSession.kt:134, 141, 163, 186
```
The listener objects are `java.lang.reflect.Proxy` instances of the SDK's own listener interfaces. Their only behaviour is to record arguments; non-void callbacks return neutral defaults (0/false/null).

### A12. OPT-IN: single read of SDK-named ADAS ids (separate button, off unless you press it)
```
Method:              The same getters as A6, A8 and A9, nothing else.
Purpose:             The ECARX SDK declares named int constants (for example names containing ADAS, LANE, ACC, BSD, TSR, TARGET).
                     After a confirmation dialog, and only when gear reads P (or you confirm Park if gear is unreadable), the
                     app reads each such id once.
Why read-only:       Same getters as known signals. Ids come from the SDK's own constant names in public interfaces, not from
                     guessing or ranges. Constants below 0x00100000 (enum values, not ids) are skipped. Only constants whose
                     name says FUNC → getFunctionValue, or SENSOR_TYPE / Sensor class → getSensorEvent and getSensorLatestValue.
                     Anything else is catalogued and never read. At most 400 reads.
Known side effects:  None known for getters. You can skip this button entirely; the catalogue of names is in the report either way.
Source/reference:    SensorDiscovery.readCatalogueOnce(), DiagnosticsViewModel.readNamedConstants()
```

### A13. Reflection over vendor classes (inspection only)
```
Method:              Class.forName(name, initialize = false), Class.getMethods/getDeclaredMethods/getDeclaredFields/
                     getDeclaredClasses/getInterfaces/getSuperclass; Field.get(null) on static constants of vendor INTERFACES only.
Purpose:             List classes, methods, parameter/return types, fields, enum constant names and constant values.
Why read-only:       Reflection metadata does not execute the inspected code. Methods are classified and listed, never invoked.
                     Field.get on an interface constant initialises that interface inside this app's process; an interface
                     initialiser can only set up its own constant fields. Constants of classes are listed WITHOUT values,
                     because a class initialiser may run arbitrary code (the smoke test checks this).
Return type:         metadata
Known side effects:  Interface initialisation inside this process only.
Source/reference:    ecarx/EcarxReflection.kt
```

## B. Android framework calls

| Call | Purpose | Why read-only |
|---|---|---|
| `PackageManager.getInstalledPackages(0)`, `getPackageInfo(pkg, GET_ACTIVITIES / GET_SERVICES / GET_RECEIVERS / GET_PROVIDERS / GET_PERMISSIONS)`, `ApplicationInfo.loadLabel` | Package inventory (brief §7) | Public metadata queries. No component is started, bound or queried. Content providers are listed, never queried. |
| `Context.checkSelfPermission(p)` | Granted/denied table | Query only. Includes a few permissions the app does not request (CAMERA, location, car.*) to document container defaults. Nothing is requested at runtime. |
| `PackageManager.getSystemAvailableFeatures()` | Feature list | Query. |
| `DisplayManager.getDisplays()`, `Display.getRealMetrics()` | Display list (a cluster/HUD display may appear) | Query. Nothing is drawn on other displays. |
| `ServiceManager.listServices()` (reflection, hidden-but-app-accessible) | Binder service names | Asks servicemanager for its name list. No service is contacted. |
| **OPT-IN toggle, default OFF:** `ServiceManager.checkService(name)` then `IBinder.getInterfaceDescriptor()` for service names matching a relevance term | AIDL interface names | `getInterfaceDescriptor` sends the framework's reserved `INTERFACE_TRANSACTION` meta-code, answered by the Binder base class / AIDL stub with the interface name before service logic runs. **Caveat:** a vendor service that overrides `onTransact` without calling the base class could see this code; that is why it is opt-in. No other transaction, `pingBinder` or `dump` is used. |
| `/system/bin/getprop` (no arguments, run as this app's UID) | Real platform identity behind App Lab's Build.* spoofing (`ro.build.display.id`, `ro.board.platform`, …) | Prints properties; with no arguments it cannot set anything. Keys matching serial/VIN/MAC/IMEI/account/token patterns are dropped, and 17-character VIN-like values are redacted, before anything is stored. Fallback: `SystemProperties.get(key)` for 8 fixed keys. |
| `System.getenv("BOOTCLASSPATH" / "SYSTEMSERVERCLASSPATH")`, `File.list()` on `/system/framework`, `/system_ext/framework`, `/product/framework`, `/vendor/framework`, `/odm/framework` | Where vendor jars live | Directory listing. |
| `ZipFile` read of vendor jars and of relevant system APKs (`ApplicationInfo.sourceDir`) | Class names, identifier strings, native library names, render-asset names | Byte parsing of `classes*.dex` (own parser, `platform/DexScanner.kt`). No ClassLoader, no `DexFile`, nothing from those files is executed. Files are opened read-only. |
| `Application.getProcessName()`, `Process.myUid()/myPid()`, `Build.*` | Environment | Query. |

## C. What the app writes (all local, none to the vehicle)

- `files/srprobe/srprobe-events.jsonl` (capture), `files/srprobe/export/*` (report files) in the app's private storage.
- On **Export**: copies to `Download/SRProbe/` through MediaStore (Android 10+).
- On **Save To Folder / USB…**: copies to the folder you pick in the system picker.
- On **Share…**: a read-only, non-exported `ReportProvider` grants the chosen app temporary read access to those files.
- No `INTERNET` permission. No network code. No settings, properties or system files are written.

## D. Found-but-never-called (by design)

| API | Why not called |
|---|---|
| `ICarFunction.setFunctionValue` and every `set*` / action method | Mutators. Refused by the guard. |
| `ICarFunction.isFunctionSupported`, `getCustomizeFunctionValue`, any other getter not in A | Name looks like a read but semantics unproven on this platform. Listed in the report as `get?`. |
| Any `Car.getXxxManager()` other than the three in A3–A5 (e.g. a perception, ADAS or AVM manager if one exists) | Unknown manager; obtaining it may bind a service. Listed for v0.2 review. |
| `ICarInfo.getCarInfoString` | May return VIN/identifiers. |
| `android.car.Car` (AAOS car service) | Reported elsewhere to throw SecurityException in App Lab; presence is checked with `initialize=false` only. |
| `com.zeekr.coreservice` SDK | Reported elsewhere to refuse third-party apps ("vehicle service not available"); package listed only. |
| Camera2 / any camera API | Out of scope for v0.1 (brief §18). No CAMERA permission. |
| Starting, binding or querying any discovered activity, service, receiver or content provider | Purpose unknown. Names listed only. |
| Any binder transaction other than the opt-in `INTERFACE_TRANSACTION` | Arbitrary transactions to unknown services are prohibited. |
| Hidden-API exemption tricks (meta-reflection, `setHiddenApiExemptions`) | Would bypass an Android security mechanism. If a hidden framework method is blocked, the report says so. |
| Brute-forcing ids or zones | Prohibited. Only fixed known ids and SDK-named constants (opt-in) are read. |

## E. Known signal table (ids read in A6–A10)

See `app/src/main/java/au/local/zeekr/srprobe/ecarx/KnownSignals.kt`. 28 entries: speed, gear, steering, brake pedal/depth, accelerator, ignition, auto-hold, indicator status and lamps, low beam, day/night, doors (zones 0x1/0x4), driver side, factory 360/AVM shown, factory camera popup, park assist, and ADAS **switch** states (AEB, FCW, LDW, LKA, BSD, RCW, LCA, LCC, drive-pilot/ACC candidate). The ADAS rows are settings, not live detections.
