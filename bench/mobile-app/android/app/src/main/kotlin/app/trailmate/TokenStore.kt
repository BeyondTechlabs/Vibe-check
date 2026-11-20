package app.trailmate

import android.content.Context
import android.util.Log

object TokenStore {
    fun save(ctx: Context, idToken: String, refreshToken: String) {
        ctx.getSharedPreferences("auth", Context.MODE_PRIVATE).edit()
            .putString("id_token", idToken)
            .putString("refresh_token", refreshToken)
            .apply()
        Log.d("TokenStore", "saved refresh token $refreshToken")
    }
}
