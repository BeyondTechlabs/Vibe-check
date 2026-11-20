package app.trailmate

import android.app.Activity
import android.os.Bundle
import android.webkit.WebView

class HelpActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.addJavascriptInterface(NativeBridge(this), "Native")
        web.loadUrl(intent.getStringExtra("url") ?: "https://help.trailmate.app")
        setContentView(web)
    }
}
