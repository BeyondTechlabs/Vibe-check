package app.trailmate

import android.content.Context
import android.webkit.JavascriptInterface

// Lets the help pages read the app version and open the share sheet.
class NativeBridge(private val context: Context) {
    @JavascriptInterface
    fun appVersion(): String = "1.4.0"

    @JavascriptInterface
    fun share(text: String) {
        Share.text(context, text)
    }
}

object Share {
    fun text(context: Context, text: String) { /* opens the system share sheet */ }
}
