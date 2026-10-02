package android.os;
/** JVM stand-in for the native android.os.SystemClock (smoke test only). */
public final class SystemClock {
    public static long elapsedRealtime() { return System.nanoTime() / 1_000_000L; }
    public static long elapsedRealtimeNanos() { return System.nanoTime(); }
    public static long uptimeMillis() { return System.nanoTime() / 1_000_000L; }
}
