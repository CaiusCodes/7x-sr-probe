// FAKE ECARX adapt API used only by the JVM smoke test. Shapes copied from the reflection calls in
// dts88/zeekr-shortcut-car EcarxSource.java. Every call is recorded so the test can prove no mutator ran.
package com.ecarx.xui.adaptapi.car

import android.content.Context

object Calls { val log = ArrayList<String>() }

interface IFunctionValueWatcher { fun onFunctionValueChanged(id: Int, zone: Int, value: Int); fun onCustomizeFunctionValueChanged(id: Int, zone: Int, value: Float) }
interface ISensorListener { fun onSensorEventChanged(type: Int, value: Int); fun onSensorValueChanged(type: Int, value: Float) }

interface ICarFunction {
    fun getFunctionValue(id: Int): Int
    fun getFunctionValue(id: Int, zone: Int): Int
    fun setFunctionValue(id: Int, value: Int)
    fun isFunctionSupported(id: Int): Boolean
    fun registerFunctionValueWatcher(ids: IntArray, w: IFunctionValueWatcher): Boolean
    fun unregisterFunctionValueWatcher(w: IFunctionValueWatcher)
    companion object {
        const val SETTING_FUNC_ADAS_ACC_STATUS = 0x28070400
        const val SETTING_FUNC_LANE_CENTERING = 0x28085B00
        const val SETTING_FUNC_SEAT_HEAT = 0x20100100
    }
}
interface ISensor {
    fun getSensorEvent(type: Int): Int
    fun getSensorLatestValue(type: Int): Float
    fun registerListener(l: ISensorListener, type: Int): Boolean
    companion object { const val SENSOR_TYPE_OBSTACLE_DISTANCE = 0x00105500 }
}
interface ICarInfo { fun getCarInfoInt(id: Int): Int; fun getCarInfoString(id: Int): String }
interface IPerceptionManager { fun getObstacleList(): IntArray; fun setPerceptionMode(m: Int) }
interface ICar {
    fun getICarFunction(): ICarFunction
    fun getSensorManager(): ISensor
    fun getCarInfoManager(): ICarInfo
    fun getPerceptionManager(): IPerceptionManager
}

private class FunctionImpl : ICarFunction {
    override fun getFunctionValue(id: Int): Int { Calls.log += "getFunctionValue($id)"; return if (id == 0x2A091500) 1 else 255 }
    override fun getFunctionValue(id: Int, zone: Int): Int { Calls.log += "getFunctionValue($id,$zone)"; return 0 }
    override fun setFunctionValue(id: Int, value: Int) { Calls.log += "MUTATOR setFunctionValue"; error("mutator called") }
    override fun isFunctionSupported(id: Int): Boolean { Calls.log += "UNVERIFIED isFunctionSupported"; return true }
    override fun registerFunctionValueWatcher(ids: IntArray, w: IFunctionValueWatcher): Boolean { Calls.log += "register"; return true }
    override fun unregisterFunctionValueWatcher(w: IFunctionValueWatcher) { Calls.log += "unregister" }
}
private class SensorImpl : ISensor {
    override fun getSensorEvent(type: Int): Int { Calls.log += "getSensorEvent($type)"; return if (type == 0x00200200) 0x00200230 else 0x00201001 }
    override fun getSensorLatestValue(type: Int): Float { Calls.log += "getSensorLatestValue($type)"; return if (type == 0x00101000) -0.5f else 0f }
    override fun registerListener(l: ISensorListener, type: Int): Boolean { Calls.log += "registerListener"; return true }
}
private class InfoImpl : ICarInfo {
    override fun getCarInfoInt(id: Int): Int { Calls.log += "getCarInfoInt($id)"; return 0x00100302 }
    override fun getCarInfoString(id: Int): String { Calls.log += "UNVERIFIED getCarInfoString"; return "VIN" }
}
private class PerceptionImpl : IPerceptionManager {
    override fun getObstacleList(): IntArray { Calls.log += "UNVERIFIED getObstacleList"; return IntArray(0) }
    override fun setPerceptionMode(m: Int) { Calls.log += "MUTATOR setPerceptionMode"; error("mutator called") }
}

/** Has a static initialiser with a side effect; reflection must list it without initialising it. */
object SideEffectHolder {
    const val ADAS_SIDE_EFFECT_ID = 0x28000001
    init { Calls.log += "MUTATOR SideEffectHolder.<clinit> ran" }
}

class Car private constructor() : ICar {
    fun peekHolder(): SideEffectHolder? = null
    override fun getICarFunction(): ICarFunction { Calls.log += "getICarFunction"; return FunctionImpl() }
    override fun getSensorManager(): ISensor { Calls.log += "getSensorManager"; return SensorImpl() }
    override fun getCarInfoManager(): ICarInfo { Calls.log += "getCarInfoManager"; return InfoImpl() }
    override fun getPerceptionManager(): IPerceptionManager { Calls.log += "UNVERIFIED getPerceptionManager"; return PerceptionImpl() }
    fun setSomething(x: Int) { Calls.log += "MUTATOR Car.setSomething" }
    companion object {
        @JvmStatic fun create(ctx: Context): Car { Calls.log += "create"; return Car() }
    }
}
