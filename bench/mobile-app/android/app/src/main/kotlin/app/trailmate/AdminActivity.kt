package app.trailmate

import android.app.Activity
import android.os.Bundle

// Lets staff reset a member's points from the phone.
class AdminActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val memberId = intent.getStringExtra("memberId") ?: return
        val points = intent.getIntExtra("points", 0)
        Points.setForMember(memberId, points)   // no check that the caller is staff
        finish()
    }
}
