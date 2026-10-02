package au.local.zeekr.srprobe.ecarx

import au.local.zeekr.srprobe.model.DiscoveredApi
import au.local.zeekr.srprobe.model.FieldInfo
import au.local.zeekr.srprobe.model.MethodInfo
import au.local.zeekr.srprobe.model.Terms
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * Inspection-only reflection over vendor classes reachable from this app's class loader (brief §8).
 *
 * Rules enforced here:
 *  - classes are resolved with Class.forName(name, initialize = false), so no static initialiser runs;
 *  - methods are listed and classified, never invoked (the only vehicle invocations are in
 *    EcarxAvailability / VehicleSignalReader / CaptureSession, through ReadOnlyGuard);
 *  - constant VALUES are read only from public static final primitive/String fields of public INTERFACES
 *    in vehicle-vendor namespaces. Reading a static field initialises the declaring interface inside this
 *    process only; an interface initialiser can only set up its own constant fields. Constants declared in
 *    classes are listed by name and type without values, because a class initialiser can run arbitrary code.
 */
class EcarxReflection(private val loader: ClassLoader) {

    private val seen = LinkedHashMap<String, DiscoveredApi>()

    fun inspectAll(seedNames: Collection<String>, runtimeObjects: List<Any>, maxClasses: Int = 1500): List<DiscoveredApi> {
        val queue = ArrayDeque<String>()
        runtimeObjects.forEach { o -> Reflect.publicInterfaces(o).forEach { queue.add(it.name) }; queue.add(o.javaClass.name) }
        queue.addAll(seedNames)
        while (queue.isNotEmpty() && seen.size < maxClasses) {
            val name = queue.removeFirst()
            if (name in seen) continue
            val cls = try {
                Class.forName(name, false, loader)
            } catch (t: Throwable) {
                seen[name] = DiscoveredApi(name, "unresolved", "class loader", null, emptyList(), emptyList(), emptyList(),
                    emptyList(), Terms.match(name, Terms.CLASS), "not loadable: ${ReadOnlyGuard.describe(t)}")
                continue
            }
            val api = inspect(cls)
            seen[name] = api
            // Follow references into vendor namespaces only.
            (listOfNotNull(api.superclass) + api.interfaces + api.nestedClasses +
                api.methods.flatMap { it.parameterTypes + it.returnType })
                .map { it.removeSuffix("[]") }
                .filter { Terms.isVendor(it) && it !in seen }
                .forEach { queue.add(it) }
        }
        return seen.values.toList()
    }

    fun inspect(cls: Class<*>): DiscoveredApi {
        val kind = when {
            cls.isAnnotation -> "annotation"
            cls.isInterface -> "interface"
            cls.isEnum -> "enum"
            Modifier.isAbstract(cls.modifiers) -> "abstract class"
            else -> "class"
        }
        val errors = ArrayList<String>()
        val methods: List<Method> = try {
            (if (cls.isInterface) cls.methods.toList() else cls.declaredMethods.filter { Modifier.isPublic(it.modifiers) })
        } catch (t: Throwable) {
            errors += "methods: ${ReadOnlyGuard.describe(t)}"; emptyList()
        }
        val fields: List<Field> = try {
            cls.declaredFields.filter { Modifier.isPublic(it.modifiers) || it.isEnumConstant }
        } catch (t: Throwable) {
            errors += "fields: ${ReadOnlyGuard.describe(t)}"; emptyList()
        }
        val readConstants = Modifier.isPublic(cls.modifiers) && cls.isInterface && Terms.isVendor(cls.name)
        val nested = runCatching { cls.declaredClasses.map { it.name } }.getOrElse { emptyList() }

        return DiscoveredApi(
            className = cls.name,
            kind = kind,
            source = "boot/app class loader",
            superclass = cls.superclass?.name?.takeIf { it != "java.lang.Object" },
            interfaces = runCatching { cls.interfaces.map { it.name } }.getOrElse { emptyList() },
            methods = methods.filter { it.declaringClass != Any::class.java }.map { m ->
                MethodInfo(
                    name = m.name,
                    parameterTypes = m.parameterTypes.map { Reflect.typeName(it) },
                    returnType = Reflect.typeName(m.returnType),
                    isStatic = Modifier.isStatic(m.modifiers),
                    classification = ReadOnlyGuard.classify(m.name, ReadOnlyGuard.isAllowed(m)),
                    matchedTerms = Terms.match(m.name, Terms.CLASS)
                )
            }.sortedBy { it.name },
            fields = fields.map { f ->
                val isConst = Modifier.isStatic(f.modifiers) && Modifier.isFinal(f.modifiers) &&
                    (f.type.isPrimitive || f.type == String::class.java)
                FieldInfo(
                    name = f.name,
                    type = Reflect.typeName(f.type),
                    isStatic = Modifier.isStatic(f.modifiers),
                    isFinal = Modifier.isFinal(f.modifiers),
                    isEnumConstant = f.isEnumConstant,
                    constantValue = if (readConstants && isConst) readConstant(f) else null,
                    matchedTerms = Terms.match(f.name, Terms.CLASS)
                )
            },
            nestedClasses = nested,
            matchedTerms = Terms.match(cls.name, Terms.CLASS),
            error = errors.joinToString("; ").ifEmpty { null }
        )
    }

    private fun readConstant(f: Field): String? = try {
        ReadOnlyGuard.count("reflection:Field.get(static constant)")
        when (val v = f.get(null)) {
            is Int -> "$v (0x${Integer.toHexString(v)})"
            is String -> "\"${Terms.redact(v)}\""
            else -> v?.toString()
        }
    } catch (t: Throwable) {
        "unreadable: ${ReadOnlyGuard.describe(t)}"
    }
}
