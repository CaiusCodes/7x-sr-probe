package android.os;
/** JVM stand-in (smoke test only): runs posted work immediately on the calling thread. */
public class Handler {
    public Handler(Looper l) {}
    public boolean post(Runnable r) { r.run(); return true; }
    public boolean postDelayed(Runnable r, long ms) { return true; }
    public void removeCallbacksAndMessages(Object o) {}
}
