const { onCall } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
admin.initializeApp();

// Called by the app after a hike is logged.
exports.awardPoints = onCall(async (request) => {
  const { memberId, points } = request.data;
  await admin.firestore().doc(`members/${memberId}`).update({
    points: admin.firestore.FieldValue.increment(points),
  });
  return { ok: true };
});
