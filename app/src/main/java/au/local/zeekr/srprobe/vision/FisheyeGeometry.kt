package au.local.zeekr.srprobe.vision

/**
 * v0.8.6: pure geometry for the 7X surround cameras (no Android, unit-tested on the JVM).
 *
 * Each 1280x1280 view is modelled as an equidistant fisheye (r = F * theta) centred in the tile. Three flat
 * "virtual cameras" per view (looking left, ahead and right) are cut out of it so the detector sees straight,
 * undistorted cars. Camera tilt and height are rough values measured from the owner's photos, so distances
 * on the top-down view are approximate.
 */
object FisheyeGeometry {

    const val SIDE = 1280
    const val F = 380.0
    const val N = SurroundDetector.SIZE

    /** One mounted camera: yaw on the car (0 = forward, 90 = left, -90 = right), tilt down, height, position. */
    data class Pose(val yawDeg: Double, val tiltDownDeg: Double, val heightM: Double, val xM: Double, val yM: Double)

    /** Front, rear, left, right (the order of the stacked stream). x forward, y right, metres from car centre. */
    val POSES = arrayOf(
        Pose(0.0, 16.0, 0.65, 2.4, 0.0),
        Pose(180.0, 23.0, 0.95, -2.4, 0.0),
        Pose(90.0, 30.0, 1.05, 0.9, -1.0),
        Pose(-90.0, 28.0, 1.05, 0.9, 1.0)
    )

    data class SubView(val yawDeg: Double, val upDeg: Double, val fovDeg: Double = 70.0)

    /** The three flat views cut from camera [cam]: looking 60 deg left, ahead, 60 deg right, aimed just below the horizon. */
    fun subViews(cam: Int): List<SubView> = listOf(-60.0, 0.0, 60.0).map { SubView(it, POSES[cam].tiltDownDeg - 8.0) }

    /** Ray (camera frame: x right, y down, z forward) through pixel (u, v) of a flat sub-view. */
    fun ray(s: SubView, u: Double, v: Double): DoubleArray {
        val fv = (N / 2.0) / Math.tan(Math.toRadians(s.fovDeg) / 2)
        val x = (u - N / 2.0) / fv; val y = (v - N / 2.0) / fv; val z = 1.0
        val a = Math.toRadians(s.upDeg)
        val y1 = y * Math.cos(a) - z * Math.sin(a); val z1 = y * Math.sin(a) + z * Math.cos(a)
        val p = Math.toRadians(s.yawDeg)
        val x2 = x * Math.cos(p) + z1 * Math.sin(p); val z2 = -x * Math.sin(p) + z1 * Math.cos(p)
        return doubleArrayOf(x2, y1, z2)
    }

    /** Fisheye pixel (within the 1280 tile) where a camera-frame ray lands. */
    fun fisheyePixel(r: DoubleArray): DoubleArray {
        val n = Math.sqrt(r[0] * r[0] + r[1] * r[1] + r[2] * r[2])
        val th = Math.acos((r[2] / n).coerceIn(-1.0, 1.0))
        val ph = Math.atan2(r[1], r[0])
        return doubleArrayOf(SIDE / 2.0 + F * th * Math.cos(ph), SIDE / 2.0 + F * th * Math.sin(ph))
    }

    /** Lookup table: for each of the N*N sub-view pixels, (sy shl 16) or sx in the tile, or -1 outside it. */
    fun lut(s: SubView): IntArray = IntArray(N * N) { k ->
        val p = fisheyePixel(ray(s, k % N + 0.5, k / N + 0.5))
        val sx = p[0].toInt(); val sy = p[1].toInt()
        if (sx in 0 until SIDE && sy in 0 until SIDE) (sy shl 16) or sx else -1
    }

    /** Where a camera ray meets the ground, as (x forward, y right) metres from the car centre; null above the horizon or beyond maxM. */
    fun ground(cam: Int, r: DoubleArray, maxM: Double = 30.0): DoubleArray? {
        val pose = POSES[cam]
        val b = Math.toRadians(pose.tiltDownDeg)
        val fwd = r[2] * Math.cos(b) - r[1] * Math.sin(b)
        val down = r[2] * Math.sin(b) + r[1] * Math.cos(b)
        if (down <= 1e-3) return null
        val t = pose.heightM / down
        val f = fwd * t; val right = r[0] * t
        if (Math.hypot(f, right) > maxM) return null
        val yaw = Math.toRadians(pose.yawDeg)
        // Camera forward points at yaw (positive = towards the car's left, i.e. negative y).
        val x = f * Math.cos(yaw) + right * Math.sin(yaw)
        val y = -f * Math.sin(yaw) + right * Math.cos(yaw)
        return doubleArrayOf(pose.xM + x, pose.yM + y)
    }
}
