package android.os;
/** JVM stand-in (smoke test only). */
public final class Looper {
    private static final Looper MAIN = new Looper();
    public static Looper getMainLooper() { return MAIN; }
}
