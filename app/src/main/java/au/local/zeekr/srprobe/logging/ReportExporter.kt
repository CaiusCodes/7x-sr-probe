package au.local.zeekr.srprobe.logging

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import android.provider.MediaStore
import au.local.zeekr.srprobe.ecarx.KnownSignal
import au.local.zeekr.srprobe.model.Availability
import au.local.zeekr.srprobe.model.MethodClass
import au.local.zeekr.srprobe.model.Terms
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import au.local.zeekr.srprobe.ui.DiagnosticsViewModel
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Builds srprobe-report.md (human), srprobe-discovery.json (machine) and copies srprobe-events.jsonl.
 * Export is local only: app storage, the public Downloads folder, a user-chosen folder (SAF), or the share
 * sheet. There is no network code in this app.
 */
class ReportExporter(private val ctx: Context, private val vm: DiagnosticsViewModel) {

    val outDir = File(ctx.filesDir, "srprobe/export").apply { mkdirs() }

    fun writeAll(): List<File> {
        vm.recorder.flush()
        val md = File(outDir, "srprobe-report.md").apply { writeText(markdown()) }
        val json = File(outDir, "srprobe-discovery.json").apply { writeText(discoveryJson().toString(1)) }
        val events = File(outDir, "srprobe-events.jsonl")
        if (vm.recorder.eventsFile.exists()) vm.recorder.eventsFile.copyTo(events, overwrite = true) else events.writeText("")
        val zip = File(outDir, "srprobe-export.zip")
        ZipOutputStream(zip.outputStream()).use { z ->
            for (f in listOf(md, json, events)) { z.putNextEntry(ZipEntry(f.name)); f.inputStream().use { it.copyTo(z) }; z.closeEntry() }
        }
        return listOf(md, events, json, zip)
    }

    /** Copies files to Downloads/SRProbe via MediaStore (Android 10+). Returns a description of where. */
    fun copyToDownloads(files: List<File>): String {
        if (Build.VERSION.SDK_INT < 29) return "Downloads copy needs Android 10+"
        val stamp = vm.recorder.now().replace(":", "").replace("-", "").substring(0, 15)
        val ok = ArrayList<String>()
        for (f in files) {
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, "${f.nameWithoutExtension}-$stamp.${f.extension}")
                put(MediaStore.MediaColumns.MIME_TYPE, mime(f))
                put(MediaStore.MediaColumns.RELATIVE_PATH, "Download/SRProbe")
            }
            val uri = ctx.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: continue
            ctx.contentResolver.openOutputStream(uri)?.use { out -> f.inputStream().use { it.copyTo(out) } }
            ok += f.name
        }
        return "Download/SRProbe: ${ok.joinToString()}"
    }

    /** Writes the files into a folder the user picked with ACTION_OPEN_DOCUMENT_TREE (e.g. a USB drive). */
    fun copyToTree(tree: Uri, files: List<File>): String {
        val docId = DocumentsContract.getTreeDocumentId(tree)
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, docId)
        val ok = ArrayList<String>()
        for (f in files) {
            val uri = DocumentsContract.createDocument(ctx.contentResolver, parent, mime(f), f.name) ?: continue
            ctx.contentResolver.openOutputStream(uri)?.use { out -> f.inputStream().use { it.copyTo(out) } }
            ok += f.name
        }
        return "Saved ${ok.size} files to the chosen folder"
    }

    private fun mime(f: File) = when (f.extension) {
        "md" -> "text/markdown"; "json" -> "application/json"; "jsonl" -> "application/x-ndjson"; "zip" -> "application/zip"
        else -> "application/octet-stream"
    }

    // ------------------------------------------------------------------ Markdown

    fun markdown(): String = buildString {
        val pk = vm.packages
        val sv = vm.services
        appendLine("# 7X SR Probe Report")
        appendLine()
        appendLine("Generated ${vm.recorder.now()} by 7X SR Probe v0.2 (READ ONLY). Safe discovery started ${vm.discoveryRunAt ?: "never"}, took ${vm.discoveryMs / 1000} s.")
        appendLine("Gear read P at discovery: ${vm.parkedAtDiscovery ?: "unknown"}.")
        appendLine()

        appendLine("## Summary")
        val st = vm.ecarx.status
        appendLine("- ECARX adapt API: class ${if (st.classPresent) "present" else "absent"}; Car ${st.car}; function ${st.function}; sensor ${st.sensor}; car info ${st.carInfo}")
        appendLine("- Known signals AVAILABLE: ${vm.signals.count { it.availability == Availability.AVAILABLE }} of ${vm.signals.size}")
        appendLine("- Visible packages: ${pk?.totalVisible ?: 0}; relevant: ${pk?.relevant?.size ?: 0}")
        appendLine("- Binder services listed: ${sv?.totalServices ?: 0}; relevant: ${sv?.relevant?.size ?: 0}")
        appendLine("- Vendor classes reflected: ${vm.apis.size}; SDK-named ADAS constants: ${vm.namedConstants.size}")
        appendLine("- Sources scanned for names: ${vm.dexScans.size}; relevant class names found: ${vm.dexScans.sumOf { it.matchingClasses.size }}")
        appendLine("- Capture events written: ${vm.recorder.eventsWritten}; unknown callback kinds: ${vm.capture?.unknownCallbacks?.size ?: 0}")
        appendLine()

        appendLine("## Read-only invocation ledger")
        appendLine("Every reflective/platform call this run made, with counts. Compare with READ_ONLY_AUDIT.md.")
        appendLine("```")
        ReadOnlyGuard.ledgerSnapshot().forEach { (k, v) -> appendLine("$v\t$k") }
        appendLine("```")
        appendLine()

        val env = vm.environment
        val isDisplay = { t: String -> t == "Displays" }
        val isPerm = { t: String -> t.startsWith("Permissions") }
        env.take(3).forEach { section(it) }
        appendLine("## Display")
        env.firstOrNull { isDisplay(it.title) }?.rows?.forEach { appendLine("- ${it.first}: ${it.second}") }
        appendLine()
        appendLine("## Permissions")
        env.firstOrNull { isPerm(it.title) }?.rows?.forEach { appendLine("- ${it.first}: ${it.second}") }
        appendLine()
        env.drop(3).filter { !isDisplay(it.title) && !isPerm(it.title) }.forEach { section(it) }

        appendLine("## Relevant packages")
        if (pk?.error != null) appendLine("Package listing failed: ${pk.error}")
        pk?.relevant?.forEach { p ->
            appendLine("### ${p.packageName}${p.label?.let { " — $it" } ?: ""}")
            appendLine("version ${p.versionName} (${p.versionCode}); ${if (p.system) "system" else "user"}; ${if (p.enabled) "enabled" else "disabled"}; terms: ${p.matchedTerms.joinToString()}")
            p.error?.let { appendLine("error: $it") }
            fun comps(title: String, list: List<au.local.zeekr.srprobe.model.ComponentRecord>) {
                if (list.isEmpty()) return
                appendLine("- $title (${list.size}, exported ${list.count { it.exported }}):")
                list.forEach { c -> appendLine("  - `${c.name}`${if (c.exported) " exported" else ""}${c.permission?.let { " perm=$it" } ?: ""}${c.authority?.let { " authority=$it" } ?: ""}") }
            }
            comps("Activities", p.activities); comps("Services", p.services); comps("Receivers", p.receivers); comps("Providers (never queried)", p.providers)
            if (p.requestedPermissions.isNotEmpty()) appendLine("- Requested permissions: ${p.requestedPermissions.joinToString()}")
            appendLine()
        }
        appendLine("<details><summary>All ${pk?.allPackageNames?.size ?: 0} visible package names</summary>")
        appendLine()
        pk?.allPackageNames?.forEach { appendLine("- $it") }
        appendLine("</details>")
        appendLine()

        appendLine("## Relevant services")
        sv?.note?.let { appendLine("Note: $it") }
        sv?.relevant?.forEach { s -> appendLine("- `${s.name}`${s.descriptor?.let { " → `$it`" } ?: ""}${s.note?.let { " ($it)" } ?: ""}") }
        appendLine()
        appendLine("<details><summary>All ${sv?.allNames?.size ?: 0} service names</summary>")
        appendLine()
        sv?.allNames?.forEach { appendLine("- $it") }
        appendLine("</details>")
        appendLine()

        appendLine("## ECARX API")
        appendLine("- Detail: ${st.detail}")
        appendLine("- Connect time: ${st.connectMs} ms")
        listOfNotNull(vm.ecarx.car, vm.ecarx.function, vm.ecarx.sensor, vm.ecarx.carInfo).forEach { o ->
            appendLine("- Runtime object `${o.javaClass.name}` implements: ${au.local.zeekr.srprobe.ecarx.Reflect.publicInterfaces(o).joinToString { it.name }}")
        }
        appendLine()

        appendLine("## Known vehicle signals")
        appendLine("Ids from the public dts88/zeekr-shortcut-car project (observed on a 7X of unstated market). ADAS rows are settings switches, not detections.")
        appendLine()
        appendLine("| Signal | Read | Id | Status | Raw | Decoded | Note |")
        appendLine("|---|---|---|---|---|---|---|")
        vm.signals.forEach { s ->
            appendLine("| ${s.label} | ${s.kind} | 0x${Integer.toHexString(s.id)}${if (s.zone != 0) "@0x" + Integer.toHexString(s.zone) else ""} | ${s.availability} | ${s.rawValue ?: ""} | ${s.decodedValue ?: ""} | ${s.note ?: ""} |")
        }
        appendLine()

        appendLine("## Relevant discovered classes")
        appendLine("Inspection only. ALLOWLISTED methods are the only ones invoked; every other method is listed, never called.")
        appendLine()
        val relevantApis = vm.apis.filter { it.matchedTerms.isNotEmpty() || it.methods.any { m -> m.classification == MethodClass.ALLOWLISTED } || it.className == ReadOnlyGuard.ECARX_CAR_CLASS }
        relevantApis.forEach { a ->
            appendLine("### `${a.className}` (${a.kind})")
            a.superclass?.let { appendLine("extends `$it`") }
            if (a.interfaces.isNotEmpty()) appendLine("implements ${a.interfaces.joinToString { "`$it`" }}")
            a.error?.let { appendLine("note: $it") }
            a.methods.forEach { m ->
                appendLine("- ${m.classification.short()} `${m.returnType} ${m.name}(${m.parameterTypes.joinToString()})`${if (m.matchedTerms.isNotEmpty()) " ← ${m.matchedTerms.joinToString()}" else ""}")
            }
            val consts = a.fields.count { it.constantValue != null }
            if (a.fields.isNotEmpty()) appendLine("- fields: ${a.fields.size} (constants read: $consts; full list in srprobe-discovery.json)")
            appendLine()
        }
        appendLine("Other vendor classes reflected (names only): ${vm.apis.filter { it !in relevantApis }.joinToString { it.className }}")
        appendLine()

        appendLine("## Candidate perception APIs")
        appendLine("Name-based leads for v0.2 review. NONE of these were invoked.")
        appendLine()
        val strongMethods = vm.apis.flatMap { a -> a.methods.filter { m -> m.classification != MethodClass.ALLOWLISTED &&
            Terms.match(m.name, Terms.STRONG).isNotEmpty() }.map { a.className to it } }
        appendLine("### Methods with perception-related names (${strongMethods.size})")
        strongMethods.take(400).forEach { (c, m) -> appendLine("- [${m.classification.short()}] `$c.${m.name}(${m.parameterTypes.joinToString()}): ${m.returnType}`") }
        appendLine()
        appendLine("### Listener interfaces (possible event sources, not subscribed)")
        vm.apis.filter { it.isListenerLike }.forEach { a -> appendLine("- `${a.className}`: ${a.methods.joinToString { it.name + "(" + it.parameterTypes.joinToString() + ")" }}") }
        appendLine()
        appendLine("### SDK-named ADAS/perception constants (${vm.namedConstants.size})")
        vm.namedConstants.forEach { c -> appendLine("- `${c.declaringClass.substringAfterLast('.')}.${c.name}` = 0x${Integer.toHexString(c.value)} (${c.matchedTerms.joinToString()})${if (c.readAs.isEmpty()) " — getter unknown, never read" else ""}") }
        appendLine()
        if (vm.namedReads.isNotEmpty()) {
            appendLine("### Opt-in single reads of SDK-named ids (${vm.namedReads.size})")
            appendLine("| Constant | Getter | Status | Raw |")
            appendLine("|---|---|---|---|")
            vm.namedReads.forEach { r -> appendLine("| ${r.constant.name} (0x${Integer.toHexString(r.constant.value)}) | ${r.kind} | ${r.availability} | ${r.raw ?: r.error ?: ""} |") }
            appendLine()
        } else {
            appendLine("Opt-in reads of these ids: not run.")
            appendLine()
        }
        appendLine("### Class names and strings found in scanned jars/APKs")
        val quiet = vm.dexScans.filter { d -> d.matchingClasses.isEmpty() && d.perceptionClasses.isEmpty() && d.endpointStrings.isEmpty() && d.manifestStrings.isEmpty() }
        appendLine("${quiet.size} scanned sources had no relevant names: ${quiet.joinToString { it.source }}")
        appendLine()
        (vm.dexScans - quiet.toSet()).forEach { d ->
            appendLine("#### ${d.source}: `${d.path}`")
            d.perceptionClasses.take(60).forEach { appendLine("- perception-like (score name) `$it`") }
            d.endpointStrings.take(60).forEach { appendLine("- endpoint string `$it`") }
            d.manifestStrings.take(40).forEach { appendLine("- manifest `$it`") }
            appendLine("dex files ${d.dexFiles}, classes ${d.totalClasses}, relevant classes ${d.matchingClasses.size}, strings ${d.matchingStrings.size}${d.note?.let { "; $it" } ?: ""}")
            if (d.nativeLibs.isNotEmpty()) appendLine("- native libs: ${d.nativeLibs.joinToString()}")
            if (d.matchingAssets.isNotEmpty()) appendLine("- assets: ${d.matchingAssets.joinToString()}")
            val cap = if (d.vendorClassNames.isEmpty()) 40 else 300
            d.matchingClasses.take(cap).forEach { appendLine("- class `$it`") }
            if (d.matchingClasses.size > cap) appendLine("- … ${d.matchingClasses.size - cap} more in srprobe-discovery.json")
            d.matchingStrings.take(if (d.vendorClassNames.isEmpty()) 30 else 150).forEach { appendLine("- string `$it`") }
            appendLine()
        }

        appendLine("## Zeekr Vision / SR indicators")
        val hints = ArrayList<String>()
        pk?.relevant?.filter { Terms.match(it.packageName + " " + (it.label ?: ""), listOf("vision", "sr", "scene", "hud", "cluster", "adas", "pilot")).isNotEmpty() }
            ?.forEach { hints += "package ${it.packageName} (${it.label})" }
        vm.dexScans.forEach { d -> d.nativeLibs.filter { Terms.match(it, Terms.RENDER).isNotEmpty() }.forEach { hints += "native lib $it in ${d.source}" } }
        vm.dexScans.forEach { d -> if (d.matchingAssets.isNotEmpty()) hints += "${d.matchingAssets.size} render/scene-named assets in ${d.source}" }
        if (hints.isEmpty()) appendLine("No obvious SR/scene component found by name.") else hints.forEach { appendLine("- $it") }
        appendLine()

        appendLine("## Unknown event sources")
        val unknown = vm.capture?.unknownCallbacks
        if (unknown.isNullOrEmpty()) appendLine("No unrecognised callbacks were received${if (vm.capture == null) " (capture not run)" else ""}.")
        else unknown.forEach { (k, v) -> appendLine("- $k × $v") }
        appendLine()

        appendLine("## Errors / permission failures")
        vm.errors.forEach { appendLine("- $it") }
        vm.signals.filter { it.availability == Availability.PERMISSION_DENIED || it.availability == Availability.ERROR }
            .forEach { appendLine("- ${it.label}: ${it.availability} ${it.note ?: ""}") }
        if (vm.errors.isEmpty()) appendLine("None recorded.")
        appendLine()

        appendLine("## Capture summary")
        val cap = vm.capture
        if (cap == null) appendLine("Capture not run.") else {
            appendLine("- Subscriptions: ${cap.subscribeSummary}")
            appendLine("- Events written: ${vm.recorder.eventsWritten}; identical values suppressed: ${vm.recorder.eventsSuppressed}")
            vm.recorder.sourceCountsSnapshot().forEach { (k, v) -> appendLine("- $k: $v") }
        }
        appendLine()
        appendLine("## Probe log")
        appendLine("```")
        vm.recorder.logLines().forEach { appendLine(it) }
        appendLine("```")
    }

    private fun StringBuilder.section(sec: au.local.zeekr.srprobe.platform.AndroidEnvironment.Section) {
        appendLine("## ${sec.title}")
        sec.rows.forEach { (k, v) -> appendLine(if (v.isEmpty()) "- $k" else "- $k: $v") }
        appendLine()
    }

    private fun MethodClass.short() = when (this) {
        MethodClass.ALLOWLISTED -> "CALLED(read-only)"
        MethodClass.READ_NAME_UNVERIFIED -> "get?"
        MethodClass.LISTENER_UNVERIFIED -> "listener?"
        MethodClass.MUTATOR_NEVER_CALLED -> "MUTATOR-never"
        MethodClass.OTHER_NOT_CALLED -> "other"
    }

    // ------------------------------------------------------------------ On-screen summary

    /** A few screens of text meant to be photographed in the car: the findings that decide what v0.2 does. */
    fun summary(): String = buildString {
        val st = vm.ecarx.status
        val pk = vm.packages
        val sv = vm.services
        appendLine("7X SR PROBE 0.2 SUMMARY   ${vm.recorder.now()}   (page 1)")
        val android = vm.environment.firstOrNull { it.title.startsWith("Android") }?.rows?.toMap() ?: emptyMap()
        val props = vm.environment.firstOrNull { it.title.startsWith("Platform") }?.rows?.toMap() ?: emptyMap()
        appendLine("Android ${android["Android release"]} SDK ${android["SDK level"]}; real build ${props["ro.build.display.id"]}")
        appendLine("ECARX: car ${st.car}; signals AVAILABLE ${vm.signals.count { it.availability == Availability.AVAILABLE }}/${vm.signals.size}; discovery ${vm.discoveryMs / 1000} s; errors ${vm.errors.size}")
        vm.errors.take(5).forEach { appendLine("  ! ${it.take(160)}") }
        appendLine("Packages visible ${pk?.totalVisible}: ${pk?.allPackageNames?.joinToString()?.take(400)}")
        appendLine("App folder scan: ${vm.appScanNote ?: "not run"}")
        val scans = vm.dexScans
        appendLine("Sources scanned ${scans.size}; with dex ${scans.count { it.dexFiles > 0 }}; unreadable ${scans.count { it.note?.contains("not readable") == true }}")
        appendLine()

        appendLine("SURROUNDING-CAR LEADS: CLASS NAMES (score, name, where; names only, nothing invoked)")
        val best = HashMap<String, Pair<Int, String>>()
        scans.forEach { d ->
            d.perceptionClasses.forEach { e ->
                val score = e.substringBefore(' ').toIntOrNull() ?: 0
                val name = e.substringAfter(' ')
                if ((best[name]?.first ?: -1) < score) best[name] = score to d.source.substringAfterLast('/')
            }
        }
        best.entries.sortedWith(Comparator { x, y -> if (y.value.first != x.value.first) y.value.first - x.value.first else x.key.compareTo(y.key) })
            .take(80).forEach { appendLine("  ${it.value.first} ${it.key}  [${it.value.second}]") }
        if (best.isEmpty()) appendLine("  (none)")
        appendLine()

        appendLine("APPS WITH THE MOST PERCEPTION-LIKE NAMES:")
        scans.filter { it.perceptionClasses.isNotEmpty() }
            .map { d -> Triple(d.source.substringAfterLast('/'), d.perceptionClasses.size, d.perceptionClasses.sumOf { it.substringBefore(' ').toIntOrNull() ?: 0 }) }
            .sortedByDescending { it.third }.take(25)
            .forEach { appendLine("  ${it.first}: ${it.second} names, score ${it.third}") }
        appendLine()

        appendLine("(page 2) VENDOR INTERFACES / ACTIONS / PROVIDERS FOUND AS STRINGS:")
        val endpoints = LinkedHashMap<String, String>()
        scans.forEach { d -> d.endpointStrings.forEach { e -> endpoints.getOrPut(e) { d.source.substringAfterLast('/') } } }
        val ranked = endpoints.entries.sortedWith(Comparator { x, y ->
            val sx = Terms.perceptionScore(x.key) + Terms.match(x.key, Terms.STRONG).size
            val sy = Terms.perceptionScore(y.key) + Terms.match(y.key, Terms.STRONG).size
            if (sy != sx) sy - sx else x.key.compareTo(y.key)
        })
        appendLine("  ${endpoints.size} distinct; top 90:")
        ranked.take(90).forEach { appendLine("  ${it.key}  [${it.value}]") }
        appendLine()

        appendLine("BINDER SERVICES (${sv?.relevant?.size} relevant of ${sv?.totalServices}) ${sv?.note ?: ""}")
        sv?.relevant?.forEach { appendLine("  ${it.name}${it.descriptor?.let { d -> " -> $d" } ?: ""}${it.note?.let { n -> " ($n)" } ?: ""}") }
        appendLine("All service names: ${sv?.allNames?.joinToString()?.take(4000)}")
        appendLine()

        appendLine("(page 3) CONFIG FILE NAMES (contents not read): ${vm.configNames.size}")
        vm.configNames.take(60).forEach { appendLine("  $it") }
        appendLine()

        appendLine("ZEEKR SDK IN FRAMEWORK JARS (package: classes):")
        scans.filter { it.vendorClassNames.isNotEmpty() }.forEach { d ->
            val pkgs = d.vendorClassNames.groupingBy { it.substringBeforeLast('.') }.eachCount()
            appendLine("  ${d.path}: ${d.totalClasses} classes, ${pkgs.size} vendor packages")
            pkgs.entries.filter { it.key.startsWith("com.zeekr") }.sortedBy { it.key }.take(60).forEach { appendLine("    ${it.key}: ${it.value}") }
        }
        appendLine("Key SDK classes (methods listed, not called):")
        vm.apis.filter { a -> listOf("Dashboard", "ACCStatus", "Adas", "ADAS", "Pilot", "Perception", "Obstacle", "Scene").any { a.className.substringAfterLast('.').contains(it) } && a.className.startsWith("com.zeekr") }
            .take(12).forEach { a ->
                appendLine("  ${a.className} (${a.kind})")
                a.methods.take(15).forEach { m -> appendLine("    ${m.returnType.substringAfterLast('.')} ${m.name}(${m.parameterTypes.joinToString { it.substringAfterLast('.') }})") }
            }
        appendLine()
        appendLine("Signals: " + vm.signals.filter { it.availability == Availability.AVAILABLE }.joinToString { "${it.label}=${it.decodedValue ?: it.rawValue}" })
        appendLine("END OF SUMMARY")
    }

    // ------------------------------------------------------------------ JSON

    fun discoveryJson(): JSONObject = JSONObject().apply {
        put("app", "7X SR Probe 0.2")
        put("generated", vm.recorder.now())
        put("ledger", JSONObject(ReadOnlyGuard.ledgerSnapshot() as Map<*, *>))
        put("environment", JSONArray().apply {
            vm.environment.forEach { s -> put(JSONObject().put("title", s.title).put("rows", JSONObject().apply { s.rows.forEach { put(it.first, it.second) } })) }
        })
        put("ecarx", JSONObject().put("detail", vm.ecarx.status.detail).put("car", vm.ecarx.status.car.name))
        put("signals", JSONArray().apply {
            vm.signals.forEach { s ->
                put(JSONObject().put("key", s.key).put("kind", s.kind.name).put("id", s.id).put("zone", s.zone)
                    .put("availability", s.availability.name).put("raw", s.rawValue ?: JSONObject.NULL)
                    .put("decoded", s.decodedValue ?: JSONObject.NULL).put("trust", KnownSignal.valueOf(s.key).trust.name))
            }
        })
        put("packages", JSONArray().apply {
            vm.packages?.relevant?.forEach { p ->
                put(JSONObject().put("package", p.packageName).put("label", p.label).put("version", p.versionName)
                    .put("versionCode", p.versionCode).put("system", p.system).put("terms", JSONArray(p.matchedTerms))
                    .put("activities", JSONArray(p.activities.map { it.name + if (it.exported) " [exported]" else "" }))
                    .put("services", JSONArray(p.services.map { it.name + if (it.exported) " [exported]" else "" }))
                    .put("receivers", JSONArray(p.receivers.map { it.name + if (it.exported) " [exported]" else "" }))
                    .put("providers", JSONArray(p.providers.map { "${it.name} authority=${it.authority}" }))
                    .put("permissions", JSONArray(p.requestedPermissions)))
            }
        })
        put("allPackages", JSONArray(vm.packages?.allPackageNames ?: emptyList<String>()))
        put("services", JSONArray().apply { vm.services?.relevant?.forEach { put(JSONObject().put("name", it.name).put("descriptor", it.descriptor ?: JSONObject.NULL)) } })
        put("allServices", JSONArray(vm.services?.allNames ?: emptyList<String>()))
        put("classes", JSONArray().apply {
            vm.apis.forEach { a ->
                put(JSONObject().put("class", a.className).put("kind", a.kind).put("super", a.superclass ?: JSONObject.NULL)
                    .put("interfaces", JSONArray(a.interfaces)).put("terms", JSONArray(a.matchedTerms)).put("error", a.error ?: JSONObject.NULL)
                    .put("methods", JSONArray(a.methods.map { "${it.classification.name} ${if (it.isStatic) "static " else ""}${it.returnType} ${it.name}(${it.parameterTypes.joinToString()})" }))
                    .put("fields", JSONArray(a.fields.map { "${it.type} ${it.name}${it.constantValue?.let { v -> " = $v" } ?: ""}${if (it.isEnumConstant) " [enum]" else ""}" }))
                    .put("nested", JSONArray(a.nestedClasses)))
            }
        })
        put("namedConstants", JSONArray().apply { vm.namedConstants.forEach { put(JSONObject().put("class", it.declaringClass).put("name", it.name).put("value", it.value).put("readAs", JSONArray(it.readAs.map { k -> k.name }))) } })
        put("namedReads", JSONArray().apply { vm.namedReads.forEach { put(JSONObject().put("name", it.constant.name).put("value", it.constant.value).put("kind", it.kind.name).put("availability", it.availability.name).put("raw", it.raw ?: JSONObject.NULL)) } })
        put("dexScans", JSONArray().apply {
            vm.dexScans.forEach { d ->
                put(JSONObject().put("source", d.source).put("path", d.path).put("dexFiles", d.dexFiles).put("classes", d.totalClasses)
                    .put("matchingClasses", JSONArray(d.matchingClasses)).put("matchingStrings", JSONArray(d.matchingStrings))
                    .put("nativeLibs", JSONArray(d.nativeLibs)).put("vendorClassNames", JSONArray(d.vendorClassNames)).put("assets", JSONArray(d.matchingAssets))
                    .put("perceptionClasses", JSONArray(d.perceptionClasses)).put("endpoints", JSONArray(d.endpointStrings)).put("manifest", JSONArray(d.manifestStrings)).put("note", d.note ?: JSONObject.NULL))
            }
        })
        put("unknownCallbacks", JSONObject((vm.capture?.unknownCallbacks ?: emptyMap<String, Long>()) as Map<*, *>))
        put("errors", JSONArray(vm.errors.toList()))
    }
}
