# READ_ONLY_AUDIT.md — 7X SR Probe v0.4

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
| `DexClassLoader` load of the framework jar holding `com.zeekr.sdk.adcu.AdcuAPI` (v0.4, only when you press Subscribe) | Reach the SDK the factory view uses | Loads the jar's classes with `initialize=false`; code runs only via the section F allowlist. |
| `Context.checkSelfPermission(p)` | Granted/denied table | Query only. Includes a few permissions the app does not request (CAMERA, location, car.*) to document container defaults. Nothing is requested at runtime. |
| `PackageManager.getSystemAvailableFeatures()` | Feature list | Query. |
| `DisplayManager.getDisplays()`, `Display.getRealMetrics()` | Display list (a cluster/HUD display may appear) | Query. Nothing is drawn on other displays. |
| `ServiceManager.listServices()` (reflection, hidden-but-app-accessible) | Binder service names | Asks servicemanager for its name list. No service is contacted. |
| **OPT-IN toggle, default OFF:** `ServiceManager.checkService(name)` then `IBinder.getInterfaceDescriptor()` for service names matching a relevance term (v0.2 adds `vdc`, `hmi`, `ihu`, `someip`, `dds`, `fusion`, `ipc`, `vendor.` to the terms) | AIDL interface names | `getInterfaceDescriptor` sends the framework's reserved `INTERFACE_TRANSACTION` meta-code, answered by the Binder base class / AIDL stub with the interface name before service logic runs. **Caveat:** a vendor service that overrides `onTransact` without calling the base class could see this code; that is why it is opt-in. No other transaction, `pingBinder` or `dump` is used. |
| `/system/bin/getprop` (no arguments, run as this app's UID) | Real platform identity behind App Lab's Build.* spoofing (`ro.build.display.id`, `ro.board.platform`, …) | Prints properties; with no arguments it cannot set anything. Keys matching serial/VIN/MAC/IMEI/account/token patterns are dropped, and 17-character VIN-like values are redacted, before anything is stored. Fallback: `SystemProperties.get(key)` for 8 fixed keys. |
| `System.getenv("BOOTCLASSPATH" / "SYSTEMSERVERCLASSPATH")`, `File.list()` on `/system/framework`, `/system_ext/framework`, `/product/framework`, `/vendor/framework`, `/odm/framework` | Where vendor jars live | Directory listing. |
| `ZipFile` read of vendor jars and of relevant system APKs (`ApplicationInfo.sourceDir`) | Class names, identifier strings, native library names, render-asset names | Byte parsing of `classes*.dex` (own parser, `platform/DexScanner.kt`). No ClassLoader, no `DexFile`, nothing from those files is executed. Files are opened read-only. |
| **v0.2:** `File.list()` on `/system/app`, `/system/priv-app`, `/system_ext/app`, `/system_ext/priv-app`, `/product/app`, `/product/priv-app`, `/vendor/app`, `/odm/app`, one level into each app folder and its `oat/<isa>/` folder | Find system APKs that App Lab's package list hides (v0.1.3 saw only 8 packages) | Directory listing. Nothing is installed, started or bound. |
| **v0.2:** `ZipFile` read of every APK found that way, read of its `oat/<isa>/*.vdex` when the APK holds no `classes.dex`, and of `AndroidManifest.xml` inside the APK | Class names, AIDL interface names, intent action and content-authority strings, manifest permission/action names | Same byte parser as above. For a `.vdex`, the parser only looks for embedded standard dex headers (`dex\n0`) and reads their name tables. The manifest's binary-XML string table is read as bytes. Nothing found is called, bound, broadcast or queried. Limits: 64 MB per dex, an 8-minute total budget, 400 APKs. |
| **v0.3:** member-level read of up to 12 APKs/jars that v0.2 tied to SR objects (ZeekrVehicleService, ZeekrCarLauncherScene3D, CarControlMultiDisplay, XCLauncher3, ZeekrCarService, the `ts-carplay-adapter.jar` SDK, or any source whose names mention SRObject / `autopilot.sr` / `soa.adcu`) | Which fields an SR object has, which class delivers it, and which service, permission and intent action guard it | `platform/DexInspector.kt` reads the dex class, field, method and prototype tables, and walks the manifest's binary-XML elements (service, provider, receiver, permission, action). Bytes only: no class is loaded, no service bound, no provider queried, no intent sent. |
| **v0.2:** `File.list()` on `/system/etc`, `/system_ext/etc`, `/product/etc`, `/vendor/etc`, `/odm/etc` (two levels) | File names of configs that would reveal a perception transport (SOME/IP, DDS, ADAS, cluster) | Directory listing only. File contents are not opened. |
| `Application.getProcessName()`, `Process.myUid()/myPid()`, `Build.*` | Environment | Query. |

## F. SR-object feed subscription (v0.4, opt-in, parked only)

A separate button, **Subscribe to SR-object feed (parked)**, off unless pressed. It receives the surrounding-vehicle ("SR object") feed the factory 3D view uses, through the same public call: `AdcuAPI.get().getNavi().registerSRObjectsObserver(observer)`. The user confirmed this step on 2026-10-02.

Every call into the Zeekr SDK (`com.zeekr.*`) goes through `ReadOnlyGuard.invokeSr`, whose allowlist (`safety/ReadOnlyGuard.kt`, `isSrAllowed`) permits only two kinds of call, and only on Zeekr-namespace classes:

| Call | Shape | Why read-only |
|---|---|---|
| Zero-argument getters: `AdcuAPI.get()`, `getNavi()`, and the `get*`/`is*` accessors on received `SRObject` / `SRObjects` / position beans | no arguments | They return the API handle or read a field off a bean already delivered to us. They take nothing and change nothing. A name beginning with a mutating verb is refused even so. |
| `registerSRObjectsObserver(observer)` / `unregisterSRObjectsObserver(observer)` | one callback-interface argument | They ask the service to **deliver** perception updates to us, and to stop. They carry no payload and send no vehicle command. This is the same subscribe the factory launcher makes. |

The observer is a `java.lang.reflect.Proxy` implementing `ISRObjectsObserver`. A Proxy can only **receive** callbacks; it cannot call back into the service. On each callback it reads the delivered `SRObjects` with the zero-argument getters above and keeps the latest snapshot in memory only. The subscription is torn down (`unregisterSRObjectsObserver`) when the page closes.

**Refused here and listed only:** everything else on these classes — all `send*` (e.g. `sendCityInfo`, `sendLineInfoInf`), every `set*`, `init*`, `recoverRegistered`, `call` / `asyncCall` / `asyncBinderCall`, `onTransact`, and any manager getter that takes arguments. If a step needs a method not on the allowlist, the guard throws `ReadOnlyViolation` and the report says where it stopped; nothing unlisted runs.

**Class loading:** `com.zeekr.sdk.adcu.AdcuAPI` is not on an ordinary app's class path on this head unit, so it is loaded from its framework jar with `DexClassLoader`. Classes are resolved with `Class.forName(name, initialize = false, …)`; a static initialiser runs only when an allowlisted call first uses the class. No hidden-API exemption or boot-classpath patching is used. If the jar cannot be loaded, or the SDK will not initialise, or the service refuses the connection, that is reported as the result.

**Not read-only, so never done here:** reading the camera/perception stream itself, sending anything on the feed interface, or keeping the subscription alive while driving.

## G. Vehicle data provider query (v0.5, opt-in, parked only)

| Call | Why it is read-only |
|---|---|
| `ContentResolver.query(uri, null, null, null, null)` | Android's read contract for a provider: returns a Cursor; cannot insert, update or delete. |
| `ContentResolver.getType(uri)` | Returns a MIME string only. |

- Only authority `com.zeekr.vehicle.data` (DataContentProvider, exported by ZeekrVehicleService, found by the v0.3 manifest scan).
- URIs tried: the root, plus `content://com.zeekr.vehicle.data/...` strings already present in the vendor's own dex (discovery). At most 40 URIs, 5 rows each.
- v0.6: the v0.5 car run showed the root URI returns a null cursor. v0.6 reads ZeekrVehicleService's dex **as bytes** (`ProviderPaths`, no class loading) and lists the `const-string` operands inside its ContentProvider subclasses, their nested classes and contract-style classes in the same package (where `UriMatcher.addURI` paths live). Path-like strings from that list (wildcard `#`/`*` segments cut off) are queried under the same authority. No paths are invented or enumerated; every queried path is a string the vendor's provider code contains.
- Enforced in `ReadOnlyGuard.queryProvider/providerType` (`isProviderAllowed`); smoke-tested.
- Never used: `insert`, `bulkInsert`, `update`, `delete`, `call`, `openFile`, `openAssetFile`, `applyBatch`, `registerContentObserver`.
- Column names that look private are dropped; VIN-like values redacted.

- v0.7 (owner approved on 2026-10-03): the v0.6 run found `com.zeekr.vehicle.someip.SomIpProvider` in ZeekrVehicleService. Its authority is admitted to the same query/getType allowlist **only** if that APK's own manifest declares that exact class as `exported=true` with no `permission`/`readPermission`, and the authority is a single `com.zeekr.` name (`ReadOnlyGuard.admitFromManifest`, smoke-tested for every refusal case). Then the same rules apply: query/getType only, root plus that provider's own const-string paths, max 30.
- v0.7 also reports each provider's manifest entry, declared method names and strings separately (names only).

The v0.5 build also reports the exact exception when the ADCU SDK jar fails to load (no new calls).

## H. Camera list (v0.8, opt-in, owner asked 2026-10-03)

The owner asked to pursue camera access (other App Lab apps record dashcam video; a public note reports one
Camera2 composite surround stream on a 7X). This step only **describes** cameras:

| Call | Why it is read-only |
|---|---|
| `CameraManager.getCameraIdList()` | Returns id strings. Does not open or power a camera. |
| `CameraManager.getCameraCharacteristics(id)` | Returns static metadata (facing, sizes, formats). Does not open a camera. |
| `Context.checkSelfPermission(CAMERA)` | Reports whether the permission is held; nothing is requested. |
| `File("/dev").list()` filtered to `video*` | Directory names only; no device node is opened. |

v0.8.1 car result: camera 2 (external) offers YUV 1280x5140 = four stacked 1280x1280 surround views.

**v0.8.2 live preview (owner approved on the decision card, 2026-10-03: "Yes, preview only").**
`SurroundPreviewActivity` declares and asks for CAMERA at run time, opens the camera offering the tall stacked
stream, and uses one `TEMPLATE_PREVIEW` repeating request into an in-memory `ImageReader`. Frames are converted
to a half-resolution 2x2 grid bitmap and shown on screen (max ~8/s). Rules:
- Parked only: refused if gear does not read P; checked every second while open; closes when gear leaves P.
- Camera closes when the screen is left (onPause).
- No recording, no saving, no encoding: no MediaRecorder, MediaCodec, file or network output (smoke-tested on the dex).
- No capture-request settings beyond the standard preview template; no vehicle calls added.
- v0.8.2 car result: works; 2x2 order is front, rear, left, right (matches dts88/zeekr-shortcut-car notes).
- v0.8.3 (lessons from dts88's notes): camera close runs on the camera thread (close can block for seconds in the
  camera service); no automatic retry when the car takes the camera back; at least 3 s between close and reopen, because
  rapid open/close around sleep can leave a stuck camera-service record that only a head-unit restart clears.

## I. On-device detection runtime (v0.8.4, owner approved bundling 2026-10-03)

TensorFlow Lite 2.16.1 (Apache-2.0) is bundled unmodified from Maven Central (checksums in
`third_party/tflite/README.md`). v0.8.4 only loads it and reports its version (`vision/DetectorRuntime`).
A later version will run a car/person/truck detector on surround frames in memory; results are drawn on screen only.
TensorFlow Lite makes no vehicle calls and the APK still has no network code (smoke-tested).

## C. What the app writes

## C. What the app writes (all local, none to the vehicle)

- v0.8.1: "Show Report As QR Codes" draws the summary text as QR codes on screen (pure computation in
  `report/QrEncoder`, no network). The owner scans them with a phone. Nothing is sent from the car.

- `files/srprobe/srprobe-events.jsonl` (capture), `files/srprobe/export/*` (report files) in the app's private storage.
- On **Export**: copies to `Download/SRProbe/` through MediaStore (Android 10+).
- On **Save To Folder / USB…**: copies to the folder you pick in the system picker.
- On **Copy Report To Clipboard (in parts)** (0.1.2): `ClipboardManager.setPrimaryClip` with up to ~120 KB of the Markdown report per press. Nothing leaves the device unless you paste it somewhere.
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
