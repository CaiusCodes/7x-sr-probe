// Fake Zeekr SR SDK surface for the JVM smoke test: used only to exercise ReadOnlyGuard.isSrAllowed.
package com.zeekr.sdk.adcu

interface ISrObsFake

class NaviFake {
    fun getNavi(): Any? = null
    fun registerSRObjectsObserver(o: ISrObsFake): Boolean = true
    fun unregisterSRObjectsObserver(o: ISrObsFake): Boolean = true
    fun sendCityInfo(o: ISrObsFake): Boolean = true        // must be refused (send*)
    fun setThing(v: Int) {}                                 // must be refused (set*)
    fun init(s: Array<String>) {}                           // must be refused (init*)
    fun getObjectID(): Long = 7L                            // zero-arg read: allowed
}
