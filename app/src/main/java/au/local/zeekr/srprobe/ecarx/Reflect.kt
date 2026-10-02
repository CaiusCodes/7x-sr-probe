package au.local.zeekr.srprobe.ecarx

import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * Reflection lookup helpers. Lookups only: nothing here invokes a method.
 *
 * The ECARX implementation classes are not public (com.zeekrlife.adaptapi.car.impl.* on the reference car),
 * so methods are looked up on the public interfaces the object implements, as EcarxSource.java does.
 */
object Reflect {

    fun publicInterfaces(target: Any): List<Class<*>> {
        val all = ArrayList<Class<*>>()
        var c: Class<*>? = target.javaClass
        while (c != null) {
            collect(c.interfaces, all)
            c = c.superclass
        }
        return all.filter { Modifier.isPublic(it.modifiers) }
    }

    private fun collect(ifaces: Array<Class<*>>, into: MutableList<Class<*>>) {
        for (i in ifaces) if (i !in into) { into += i; collect(i.interfaces, into) }
    }

    fun findPublic(target: Any, name: String, vararg params: Class<*>): Method? {
        for (t in publicInterfaces(target)) match(t.methods, name, params)?.let { return it }
        val m = match(target.javaClass.methods, name, params) ?: return null
        return if (Modifier.isPublic(m.declaringClass.modifiers)) m else null
    }

    /** (int[] | int, SomeListenerInterface) — the shape of registerFunctionValueWatcher. */
    fun findWithTrailingInterface(target: Any, name: String, first: Class<*>): Method? =
        publicInterfaces(target).flatMap { it.methods.toList() }.firstOrNull {
            it.name == name && it.parameterTypes.size == 2 && it.parameterTypes[0] == first && it.parameterTypes[1].isInterface
        }

    /** (SomeListenerInterface, int) — the shape of ISensor.registerListener. */
    fun findWithLeadingInterface(target: Any, name: String, second: Class<*>): Method? =
        publicInterfaces(target).flatMap { it.methods.toList() }.firstOrNull {
            it.name == name && it.parameterTypes.size == 2 && it.parameterTypes[0].isInterface && it.parameterTypes[1] == second
        }

    /** (SomeListenerInterface) — the shape of unregisterFunctionValueWatcher. */
    fun findWithOnlyInterface(target: Any, name: String): Method? =
        publicInterfaces(target).flatMap { it.methods.toList() }.firstOrNull {
            it.name == name && it.parameterTypes.size == 1 && it.parameterTypes[0].isInterface
        }

    private fun match(methods: Array<Method>, name: String, params: Array<out Class<*>>): Method? =
        methods.firstOrNull { it.name == name && it.parameterTypes.contentEquals(params) }

    fun typeName(c: Class<*>): String = if (c.isArray) typeName(c.componentType!!) + "[]" else c.name
}
