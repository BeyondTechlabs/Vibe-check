package app.trailmate

// Writes a member's points through the app's own data layer.
object Points {
    fun setForMember(memberId: String, points: Int) {
        PointsRepository.set(memberId, points)
    }
}

object PointsRepository {
    private val cache = mutableMapOf<String, Int>()
    fun set(memberId: String, points: Int) { cache[memberId] = points }
}
