package au.local.zeekr.srprobe.ui

import android.annotation.SuppressLint
import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.webkit.ConsoleMessage
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.FrameLayout
import android.view.Gravity

/**
 * v0.9.0: the Zeekr Vision screen, driven only by simulated traffic (READ_ONLY_AUDIT.md section J).
 *
 * Shows the bundled page assets/vision/index.html in a WebView. The page draws the 3D scene and generates its own
 * mock traffic. Nothing here touches the vehicle, the cameras or the network: network loads are blocked, the page
 * only reads files bundled in the APK, and there is no JavaScript bridge into the app.
 */
class VisionActivity : Activity() {

    private var web: WebView? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val w = WebView(this)
        w.setBackgroundColor(Color.rgb(0xEE, 0xF0, 0xF2))
        val s = w.settings
        s.javaScriptEnabled = true
        s.blockNetworkLoads = true
        s.allowContentAccess = false
        s.domStorageEnabled = true
        s.mediaPlaybackRequiresUserGesture = false
        w.webViewClient = object : WebViewClient() {
            // Only bundled files may load; any other address is refused.
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean =
                !request.url.toString().startsWith(PAGE_DIR)
        }
        w.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(m: ConsoleMessage): Boolean {
                Log.i(TAG, "${m.messageLevel()}: ${m.message()} (${m.lineNumber()})")
                return true
            }
        }
        w.systemUiVisibility = View.SYSTEM_UI_FLAG_FULLSCREEN or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION or
            View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY or View.SYSTEM_UI_FLAG_LAYOUT_STABLE
        val root = FrameLayout(this)
        root.addView(w, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        val close = Button(this).apply { text = "Close"; isAllCaps = false; textSize = 16f; alpha = 0.85f; setOnClickListener { finish() } }
        root.addView(close, FrameLayout.LayoutParams(FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT,
            Gravity.BOTTOM or Gravity.START).apply { setMargins(24, 24, 24, 24) })
        setContentView(root)
        w.loadUrl(PAGE_DIR + "index.html")
        web = w
    }

    override fun onResume() { super.onResume(); web?.onResume() }
    override fun onPause() { web?.onPause(); super.onPause() }

    override fun onDestroy() {
        web?.let { it.stopLoading(); it.destroy() }
        web = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "ZeekrVision"
        const val PAGE_DIR = "file:///android_asset/vision/"
    }
}
