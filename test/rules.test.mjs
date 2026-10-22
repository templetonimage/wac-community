// WAC Firestore rules tests — run against the Firestore emulator.
// Each ALLOW case mirrors a real write/read the WAC app makes (function name in the label);
// each DENY case is an abuse path.
import { test, before, after, beforeEach } from "node:test";
import { readFileSync } from "node:fs";
import { initializeTestEnvironment, assertSucceeds, assertFails } from "@firebase/rules-unit-testing";
import {
  doc, getDoc, setDoc, updateDoc, addDoc, deleteDoc, collection, getDocs, query, where,
  increment, arrayUnion, runTransaction,
} from "firebase/firestore";

let env;
const ADMIN = { uid: "adminUid", email: "nate@templetonimage.com" };
const ALICE = { uid: "alice", email: "alice@x.com" };
const BOB = { uid: "bob", email: "bob@x.com" };
const EXPERT = { uid: "expert", email: "malik@x.com" };
const RESTARTER = { uid: "rs", email: "rs@x.com" };
const FAKEADMIN = { uid: "fake", email: "nate@templetonimage.com.evil.com" };

const db = (u) => (u ? env.authenticatedContext(u.uid, { email: u.email }) : env.unauthenticatedContext()).firestore();
const reg = (u, id) => doc(db(u), "wac_registry", id || u.uid);

before(async () => {
  env = await initializeTestEnvironment({ projectId: "demo-wac", firestore: { rules: readFileSync("firestore.rules", "utf8") } });
});
after(async () => { await env.cleanup(); });

beforeEach(async () => {
  await env.clearFirestore();
  await env.withSecurityRulesDisabled(async (ctx) => {
    const f = ctx.firestore();
    await setDoc(doc(f, "wac_registry/alice"), { name: "Alice", email: "alice@x.com", uid: "alice", points: 50, lifetimePoints: 80, totalPosts: 3, isPro: false, isExpert: false, rounds: ["R2"], trialUntil: null });
    await setDoc(doc(f, "wac_registry/bob"), { name: "Bob", email: "bob@x.com", uid: "bob", points: 20, lifetimePoints: 20, totalPosts: 1, isPro: true, rounds: ["R2"] });
    await setDoc(doc(f, "wac_registry/expert"), { name: "Malik", email: "malik@x.com", uid: "expert", points: 0, isExpert: true, rounds: [] });
    await setDoc(doc(f, "wac_registry/rs"), { name: "Re", email: "rs@x.com", uid: "rs", points: 5, lifetimePoints: 45, totalPosts: 0,
      restartedAt: 1, restartPtsPending: 10, restartLifetimeCredited: true, ambassadorBadge: true, ambassadorPtsPending: 25, ambassadorLifetimeCredited: true });
    await setDoc(doc(f, "wac_registry/alice/siteBriefs/b1"), { name: "Brief" });
    await setDoc(doc(f, "posts/postBob"), { author: "Bob", authorUid: "bob", text: "hi", url: "", props: [], propsCount: 0, replies: [], timestamp: 1 });
    await setDoc(doc(f, "posts/pvrBob"), { author: "Bob", authorUid: "bob", type: "pvr", pvr_url: "https://b.com", pvr_prompt: "p", props: ["Zed"], propsCount: 1, replies: [{ name: "Zed", uid: "zed", text: "x", timestamp: 1 }] });
    await setDoc(doc(f, "posts/respExpert"), { authorUid: "expert", type: "expert-response", body: "resp", props: [], propsCount: 0, replies: [] });
    await setDoc(doc(f, "submissions/subAlice"), { authorUid: "alice", url: "https://a.com", note: "n", pts: 17, round: "R2", weekIdx: 2 });
    await setDoc(doc(f, "submissions/subBob"), { authorUid: "bob", url: "https://b.com", note: "n", pts: 10, round: "R2", weekIdx: 2 });
    await setDoc(doc(f, "engagements/engAlice"), { authorUid: "alice", targetUrl: "https://b.com", pts: 2, round: "R2" });
    await setDoc(doc(f, "engagements/engBob"), { authorUid: "bob", targetUrl: "https://a.com", pts: 2, round: "R2" });
    await setDoc(doc(f, "trackers/alice"), { uid: "alice", tracked: {} });
    await setDoc(doc(f, "trackers/bob"), { uid: "bob", tracked: {} });
    await setDoc(doc(f, "wac_community_pts/cp1"), { uid: "alice", pts: 2, action: "x", round: "R2" });
    await setDoc(doc(f, "expert_reviews/erAlice"), { requesterUid: "alice", requesterName: "Alice", requesterEmail: "alice@x.com", pageUrl: "https://a.com", feedbackRequest: "f", monthKey: "2026-10", status: "pending", createdAt: 1 });
    await setDoc(doc(f, "expert_reviews/erBob"), { requesterUid: "bob", requesterName: "Bob", requesterEmail: "bob@x.com", pageUrl: "https://b.com", feedbackRequest: "f", monthKey: "2026-10", status: "responded", createdAt: 1 });
    await setDoc(doc(f, "wac_backlinks/bob"), { uid: "bob", siteUrl: "https://b.com", isActive: true });
    await setDoc(doc(f, "wac_coworking_sessions/s1"), { label: "Cowork", active: true, calendarUrl: "https://calendar.app.google/x" });
    await setDoc(doc(f, "wac_coworking_sessions/_visibility"), { visible: true });
    await setDoc(doc(f, "announcements/a1"), { title: "t", body: "b" });
    await setDoc(doc(f, "resources/r1"), { title: "t", url: "https://x.com" });
    await setDoc(doc(f, "bug_reports/b1"), { uid: "bob", message: "bug" });
    await setDoc(doc(f, "platform_errors/e1"), { message: "err" });
    await setDoc(doc(f, "wac_action_plan_memory/bob"), { items: [] });
    await setDoc(doc(f, "wac_copy_assist/bob"), { entries: [] });
    await setDoc(doc(f, "wac_seo_analysis/bob"), { entries: [] });
    await setDoc(doc(f, "wac_config/settings"), { proSaleRound: "R2" });
  });
});

// ── Outsiders ─────────────────────────────────────────────
test("DENY signed-out read of registry", () => assertFails(getDoc(doc(db(null), "wac_registry/alice"))));
test("DENY signed-out list of expert_reviews (was public)", () => assertFails(getDocs(collection(db(null), "expert_reviews"))));
test("DENY signed-out read of one expert_review", () => assertFails(getDoc(doc(db(null), "expert_reviews/erAlice"))));
test("DENY signed-out write anywhere", () => assertFails(setDoc(doc(db(null), "posts/x"), { authorUid: "x" })));
test("DENY unknown collection write", () => assertFails(setDoc(doc(db(ALICE), "evil/x"), { a: 1 })));
test("DENY unknown collection read", () => assertFails(getDoc(doc(db(ALICE), "evil/x"))));
test("DENY wac_config read from browser", () => assertFails(getDoc(doc(db(ADMIN), "wac_config/settings"))));
test("DENY look-alike admin email", () => assertFails(updateDoc(reg(FAKEADMIN, "bob"), { isPro: false })));

// ── Registry: member paths the app uses ───────────────────
test("ALLOW member reads registry (directory/leaderboard)", () => assertSucceeds(getDocs(collection(db(ALICE), "wac_registry"))));
test("ALLOW bootApp: lastLogin on own doc", () => assertSucceeds(updateDoc(reg(ALICE), { lastLogin: Date.now() })));
test("ALLOW submitPost: points +1 / lifetime +1", () => assertSucceeds(updateDoc(reg(ALICE), { points: increment(1), lifetimePoints: increment(1) })));
test("ALLOW submitUpdate: +17 pts, +1 post", () => assertSucceeds(updateDoc(reg(ALICE), { points: increment(17), totalPosts: increment(1), lifetimePoints: increment(17) })));
test("ALLOW deleteSubmission: -17 pts, -1 post", () => assertSucceeds(updateDoc(reg(ALICE), { points: increment(-17), totalPosts: increment(-1), lifetimePoints: increment(-17) })));
test("ALLOW saveListing: +15 backlink", () => assertSucceeds(updateDoc(reg(ALICE), { points: increment(15), lifetimePoints: increment(15) })));
test("ALLOW removeListing: -15 backlink", () => assertSucceeds(updateDoc(reg(ALICE), { points: increment(-15), lifetimePoints: increment(-15) })));
test("ALLOW submitRER: +10", () => assertSucceeds(updateDoc(reg(ALICE), { points: increment(10), lifetimePoints: increment(10) })));
test("ALLOW checkAllStar: isAllStar true", () => assertSucceeds(updateDoc(reg(ALICE), { isAllStar: true })));
test("ALLOW saveProfile: business/type/ig/website/photoURL", () => assertSucceeds(updateDoc(reg(ALICE), { business: "Photo", type: "Wedding", ig: "@alice", website: "https://a.com", photoURL: "data:image/jpeg;base64,AAAA" })));
test("ALLOW removeProfilePhoto", () => assertSucceeds(updateDoc(reg(ALICE), { photoURL: "" })));
test("ALLOW snoozeRestartModal", () => assertSucceeds(updateDoc(reg(ALICE), { restartSnoozedUntil: Date.now() + 1000 })));
test("ALLOW gsSave: activeSiteBriefId", () => assertSucceeds(updateDoc(reg(ALICE), { activeSiteBriefId: "b1" })));
test("ALLOW _creditPendingRestartPts: restart +10 and ambassador +25 credited once (transaction)", () =>
  assertSucceeds(runTransaction(db(RESTARTER), async (tx) => {
    const r = doc(db(RESTARTER), "wac_registry/rs");
    await tx.get(r);
    tx.set(doc(db(RESTARTER), "wac_community_pts/restart_rs"), { uid: "rs", name: "Re", action: "restart", type: "restart", pts: 10, round: "R2", ts: 1 });
    tx.set(doc(db(RESTARTER), "wac_community_pts/restart_ambassador_rs"), { uid: "rs", name: "Re", action: "restart_ambassador", type: "restart_ambassador", pts: 25, round: "R2", ts: 1 });
    tx.update(r, { restartPtsPending: 0, restartPtsAwardedAt: 2, ambassadorPtsPending: 0, ambassadorPtsAwardedAt: 2, points: increment(35) });
  })));
test("ALLOW credit restart only (+10)", () => assertSucceeds(updateDoc(reg(RESTARTER), { restartPtsPending: 0, restartPtsAwardedAt: 2, points: increment(10) })));
test("DENY credit more than pending", () => assertFails(updateDoc(reg(RESTARTER), { restartPtsPending: 0, restartPtsAwardedAt: 2, points: increment(30) })));
test("DENY credit without zeroing pending (repeatable)", () => assertFails(updateDoc(reg(RESTARTER), { restartPtsAwardedAt: 2, points: increment(10) })));
test("DENY credit twice", async () => {
  await updateDoc(reg(RESTARTER), { restartPtsPending: 0, restartPtsAwardedAt: 2, points: increment(10) });
  await assertFails(updateDoc(reg(RESTARTER), { restartPtsPending: 0, restartPtsAwardedAt: 3, points: increment(10) }));
});
test("DENY credit for member with nothing pending", () => assertFails(updateDoc(reg(ALICE), { restartPtsPending: 0, restartPtsAwardedAt: 2, points: increment(10) })));
test("DENY credit that also inflates lifetimePoints", () => assertFails(updateDoc(reg(RESTARTER), { restartPtsPending: 0, restartPtsAwardedAt: 2, points: increment(10), lifetimePoints: increment(10) })));

// Registry abuse
test("DENY self-grant Pro", () => assertFails(updateDoc(reg(ALICE), { isPro: true })));
test("DENY self-grant trial", () => assertFails(updateDoc(reg(ALICE), { trialUntil: Date.now() + 9e9 })));
test("DENY self-grant Expert", () => assertFails(updateDoc(reg(ALICE), { isExpert: true })));
test("DENY self-grant VIP/Founder", () => assertFails(updateDoc(reg(ALICE), { isVIP: true, isFounder: true })));
test("DENY self-add round", () => assertFails(updateDoc(reg(ALICE), { rounds: arrayUnion("R3") })));
test("DENY restart self-grant (window closed)", () => assertFails(updateDoc(reg(ALICE), { restartedAt: 1, restartAccessThroughUTC: 9e12, rounds: arrayUnion("R2"), restartPtsPending: 10, lifetimePoints: increment(10), restartLifetimeCredited: true })));
test("DENY ambassador self-grant (proof window closed)", () => assertFails(updateDoc(reg(ALICE), { ambassadorBadge: true, ambassadorPtsPending: 25, lifetimePoints: increment(25), ambassadorLifetimeCredited: true })));
test("DENY setting own pending points", () => assertFails(updateDoc(reg(ALICE), { restartPtsPending: 25 })));
test("DENY points jump +26", () => assertFails(updateDoc(reg(ALICE), { points: increment(26), lifetimePoints: increment(26) })));
test("DENY points set to 9999", () => assertFails(updateDoc(reg(ALICE), { points: 9999, lifetimePoints: 10029 })));
test("DENY points without matching lifetime", () => assertFails(updateDoc(reg(ALICE), { points: increment(5) })));
test("DENY lifetime-only inflation", () => assertFails(updateDoc(reg(ALICE), { lifetimePoints: increment(25) })));
test("DENY totalPosts +5", () => assertFails(updateDoc(reg(ALICE), { totalPosts: increment(5) })));
test("DENY points as string", () => assertFails(updateDoc(reg(ALICE), { points: "60", lifetimePoints: 90 })));
test("DENY isAllStar false (only the badge award is allowed)", () => assertFails(updateDoc(reg(ALICE), { isAllStar: false })));
test("DENY change own name/email", () => assertFails(updateDoc(reg(ALICE), { name: "Admin", email: "nate@templetonimage.com" })));
test("DENY nudge counter reset", () => assertFails(updateDoc(reg(ALICE), { nudgeCount: 0 })));
test("DENY oversized photo", () => assertFails(updateDoc(reg(ALICE), { photoURL: "x".repeat(300001) })));
test("DENY website not a string", () => assertFails(updateDoc(reg(ALICE), { website: { a: 1 } })));
test("DENY write another member's registry", () => assertFails(updateDoc(reg(ALICE, "bob"), { lastLogin: 1 })));
test("DENY create own registry doc", () => assertFails(setDoc(doc(db({ uid: "newbie", email: "n@x.com" }), "wac_registry/newbie"), { name: "N", isPro: true })));
test("DENY member deletes own registry", () => assertFails(deleteDoc(reg(ALICE))));
test("ALLOW siteBriefs own read/write/delete", async () => {
  await assertSucceeds(setDoc(doc(db(ALICE), "wac_registry/alice/siteBriefs/b2"), { name: "x" }, { merge: true }));
  await assertSucceeds(getDoc(doc(db(ALICE), "wac_registry/alice/siteBriefs/b1")));
  await assertSucceeds(deleteDoc(doc(db(ALICE), "wac_registry/alice/siteBriefs/b2")));
});
test("DENY read another's siteBriefs", () => assertFails(getDoc(doc(db(BOB), "wac_registry/alice/siteBriefs/b1"))));

// Registry: admin paths
test("ALLOW admin addRegistryMember", () => assertSucceeds(setDoc(doc(db(ADMIN), "wac_registry/newUid"), { name: "N", email: "n@x.com", uid: "newUid", rounds: ["R2"], points: 0, isPro: false })));
test("ALLOW admin toggleRegistryFlag isExpert / toggleProAccess / setTrialAccess", async () => {
  await assertSucceeds(updateDoc(doc(db(ADMIN), "wac_registry/alice"), { isExpert: true }));
  await assertSucceeds(updateDoc(doc(db(ADMIN), "wac_registry/alice"), { isPro: true, proSince: 1 }));
  await assertSucceeds(updateDoc(doc(db(ADMIN), "wac_registry/alice"), { trialUntil: 9e12 }));
});
test("ALLOW admin adminSetMemberPoints (any amount)", () => assertSucceeds(updateDoc(doc(db(ADMIN), "wac_registry/alice"), { points: 500, lifetimePoints: increment(450) })));
test("ALLOW admin removeRegistryMember", () => assertSucceeds(deleteDoc(doc(db(ADMIN), "wac_registry/bob"))));
test("ALLOW admin adminAwardAttendance: +5 to another member", () => assertSucceeds(updateDoc(doc(db(ADMIN), "wac_registry/bob"), { points: increment(5), lifetimePoints: increment(5) })));

// ── Feed ──────────────────────────────────────────────────
test("ALLOW member reads feed", () => assertSucceeds(getDocs(collection(db(ALICE), "posts"))));
test("ALLOW submitPost", () => assertSucceeds(addDoc(collection(db(ALICE), "posts"), { author: "Alice", authorUid: "alice", text: "hi", url: "", props: [], propsCount: 0, timestamp: 1 })));
test("ALLOW submitPVR", () => assertSucceeds(addDoc(collection(db(ALICE), "posts"), { author: "Alice", authorUid: "alice", type: "pvr", pvr_url: "https://a.com", pvr_prompt: "p", weekIdx: 1, replies: [], props: [], propsCount: 0, timestamp: 1 })));
test("ALLOW submitRER feed post", () => assertSucceeds(addDoc(collection(db(ALICE), "posts"), { author: "Alice", authorUid: "alice", type: "rer", reviewId: "erAlice", pageUrl: "https://a.com", feedbackRequest: "f", monthKey: "2026-10", replies: [], props: [], propsCount: 0, timestamp: 1 })));
test("ALLOW confirmProps on someone else's post", () => assertSucceeds(updateDoc(doc(db(ALICE), "posts/postBob"), { props: ["Alice"], propsCount: 1 })));
test("ALLOW confirmProps on post that already has props", () => assertSucceeds(updateDoc(doc(db(ALICE), "posts/pvrBob"), { props: ["Zed", "Alice"], propsCount: 2 })));
test("ALLOW submitPostReply on someone else's post", () => assertSucceeds(updateDoc(doc(db(ALICE), "posts/postBob"), { replies: arrayUnion({ name: "Alice", uid: "alice", text: "nice", timestamp: 1 }) })));
test("ALLOW submitPVRReply", () => assertSucceeds(updateDoc(doc(db(ALICE), "posts/pvrBob"), { replies: arrayUnion({ name: "Alice", uid: "alice", text: "fb", timestamp: 2 }) })));
test("ALLOW savePostEdit own", () => assertSucceeds(updateDoc(doc(db(BOB), "posts/postBob"), { text: "edited", url: "https://b.com" })));
test("ALLOW savePVREdit own", () => assertSucceeds(updateDoc(doc(db(BOB), "posts/pvrBob"), { pvr_prompt: "new" })));
test("ALLOW deletePost own", () => assertSucceeds(deleteDoc(doc(db(BOB), "posts/postBob"))));
test("ALLOW admin submitAdminPVRComment", () => assertSucceeds(updateDoc(doc(db(ADMIN), "posts/pvrBob"), { replies: arrayUnion({ name: "Nate", uid: "adminUid", text: "c", isAdminComment: true, timestamp: 3 }) })));
test("ALLOW admin clearFeedPostsByWeek", () => assertSucceeds(deleteDoc(doc(db(ADMIN), "posts/postBob"))));
test("DENY post as someone else", () => assertFails(addDoc(collection(db(ALICE), "posts"), { authorUid: "bob", text: "fake", props: [], propsCount: 0 })));
test("DENY post with pre-loaded props", () => assertFails(addDoc(collection(db(ALICE), "posts"), { authorUid: "alice", text: "x", props: ["A", "B"], propsCount: 99 })));
test("DENY member creates fake expert-response post", () => assertFails(addDoc(collection(db(ALICE), "posts"), { authorUid: "alice", type: "expert-response", body: "fake", props: [], propsCount: 0, replies: [] })));
test("DENY edit someone else's post text", () => assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { text: "hacked" })));
test("DENY delete someone else's post", () => assertFails(deleteDoc(doc(db(ALICE), "posts/postBob"))));
test("DENY props count inflated", () => assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { props: ["Alice"], propsCount: 50 })));
test("DENY wiping others' props", () => assertFails(updateDoc(doc(db(ALICE), "posts/pvrBob"), { props: [], propsCount: 0 })));
test("DENY reply signed as another member", () => assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { replies: arrayUnion({ name: "Bob", uid: "bob", text: "x", timestamp: 1 }) })));
test("DENY fake admin comment from member", () => assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { replies: arrayUnion({ name: "Nate", uid: "alice", text: "x", isAdminComment: true, timestamp: 1 }) })));
test("DENY rewriting the replies list", () => assertFails(updateDoc(doc(db(ALICE), "posts/pvrBob"), { replies: [{ name: "Alice", uid: "alice", text: "x", timestamp: 1 }] })));
test("DENY reply plus text change", () => assertFails(updateDoc(doc(db(ALICE), "posts/postBob"), { text: "x", replies: arrayUnion({ name: "Alice", uid: "alice", text: "x", timestamp: 1 }) })));

// ── Weekly challenge ──────────────────────────────────────
test("ALLOW submitUpdate creates own submission (17 pts)", () => assertSucceeds(addDoc(collection(db(ALICE), "submissions"), { author: "Alice", authorUid: "alice", round: "R2", weekIdx: 3, url: "https://a.com", note: "n", format: "Blog Post", challengeCompleted: true, hasScreenshot: true, pts: 17, isLate: false, timestamp: 1 })));
test("ALLOW member reads submissions (dedup queries)", () => assertSucceeds(getDocs(query(collection(db(ALICE), "submissions"), where("authorUid", "==", "alice"), where("round", "==", "R2")))));
test("ALLOW editSubmission own url/note", () => assertSucceeds(updateDoc(doc(db(ALICE), "submissions/subAlice"), { url: "https://a2.com", note: "n2", editedAt: 2 })));
test("ALLOW deleteSubmission own", () => assertSucceeds(deleteDoc(doc(db(ALICE), "submissions/subAlice"))));
test("ALLOW submitEngagement own", () => assertSucceeds(addDoc(collection(db(ALICE), "engagements"), { author: "Alice", authorUid: "alice", round: "R2", weekIdx: 3, targetUrl: "https://b.com", note: "n", type: "comment", hasScreenshot: true, pts: 2, timestamp: 1 })));
test("ALLOW submitPVRReply engagement (no round field)", () => assertSucceeds(addDoc(collection(db(ALICE), "engagements"), { author: "Alice", authorUid: "alice", weekIdx: 3, targetUrl: "", note: "PVR feedback on bob", type: "PVR Feedback", hasScreenshot: false, pts: 2, isPVR: true, timestamp: 1 })));
test("ALLOW admin adminOpenEditSubmission (pts change)", () => assertSucceeds(updateDoc(doc(db(ADMIN), "submissions/subBob"), { url: "https://b2.com", pts: 5 })));
test("ALLOW admin backfillRoundTags", () => assertSucceeds(updateDoc(doc(db(ADMIN), "engagements/engBob"), { round: "R2" })));
test("DENY submission as someone else", () => assertFails(addDoc(collection(db(ALICE), "submissions"), { authorUid: "bob", pts: 10 })));
test("DENY submission worth 500 pts", () => assertFails(addDoc(collection(db(ALICE), "submissions"), { authorUid: "alice", pts: 500 })));
test("DENY negative-points submission", () => assertFails(addDoc(collection(db(ALICE), "submissions"), { authorUid: "alice", pts: -20 })));
test("DENY member edits own submission pts", () => assertFails(updateDoc(doc(db(ALICE), "submissions/subAlice"), { pts: 25 })));
test("DENY edit someone else's submission", () => assertFails(updateDoc(doc(db(ALICE), "submissions/subBob"), { note: "x" })));
test("DENY delete someone else's submission", () => assertFails(deleteDoc(doc(db(ALICE), "submissions/subBob"))));
test("DENY member edits own engagement", () => assertFails(updateDoc(doc(db(ALICE), "engagements/engAlice"), { pts: 20 })));
test("DENY delete someone else's engagement", () => assertFails(deleteDoc(doc(db(ALICE), "engagements/engBob"))));

// Trackers
test("ALLOW toggleCheck own tracker (merge)", () => assertSucceeds(setDoc(doc(db(ALICE), "trackers/alice"), { uid: "alice", tracked: { w1: [true] } }, { merge: true })));
test("ALLOW toggleCheck creates own tracker", async () => {
  await env.withSecurityRulesDisabled((c) => deleteDoc(doc(c.firestore(), "trackers/alice")));
  await assertSucceeds(setDoc(doc(db(ALICE), "trackers/alice"), { uid: "alice", tracked: { w1: [true] } }, { merge: true }));
});
test("ALLOW member reads own tracker", () => assertSucceeds(getDoc(doc(db(ALICE), "trackers/alice"))));
test("ALLOW admin adminToggleCheck + loadTrackerReport", async () => {
  await assertSucceeds(setDoc(doc(db(ADMIN), "trackers/bob"), { uid: "bob", tracked: { w2: [true] } }, { merge: true }));
  await assertSucceeds(getDocs(collection(db(ADMIN), "trackers")));
});
test("DENY write someone else's tracker", () => assertFails(setDoc(doc(db(ALICE), "trackers/bob"), { uid: "bob", tracked: {} }, { merge: true })));
test("DENY extra fields on tracker", () => assertFails(setDoc(doc(db(ALICE), "trackers/alice"), { uid: "alice", tracked: {}, isPro: true }, { merge: true })));
test("DENY list all trackers as member", () => assertFails(getDocs(collection(db(ALICE), "trackers"))));

// Community points log
test("ALLOW logCommunityPts own", () => assertSucceeds(addDoc(collection(db(ALICE), "wac_community_pts"), { uid: "alice", name: "Alice", action: "Coworking RSVP", pts: 2, round: "R2", ts: 1 })));
test("ALLOW member reads community pts (dashboard)", () => assertSucceeds(getDocs(query(collection(db(ALICE), "wac_community_pts"), where("round", "==", "R2")))));
test("ALLOW admin revokeAmbassadorProof deletes log doc", () => assertSucceeds(deleteDoc(doc(db(ADMIN), "wac_community_pts/cp1"))));
test("DENY community pts for someone else", () => assertFails(addDoc(collection(db(ALICE), "wac_community_pts"), { uid: "bob", pts: 2 })));
test("DENY community pts +500", () => assertFails(addDoc(collection(db(ALICE), "wac_community_pts"), { uid: "alice", pts: 500 })));
test("DENY member edits/deletes community pts", async () => {
  await assertFails(updateDoc(doc(db(ALICE), "wac_community_pts/cp1"), { pts: 25 }));
  await assertFails(deleteDoc(doc(db(ALICE), "wac_community_pts/cp1")));
});

// ── Expert Reviews ────────────────────────────────────────
test("ALLOW submitRER own request", () => assertSucceeds(addDoc(collection(db(ALICE), "expert_reviews"), { requesterUid: "alice", requesterName: "Alice", requesterEmail: "alice@x.com", pageUrl: "https://a.com", feedbackRequest: "f", monthKey: "2026-11", status: "pending", createdAt: 1 })));
test("ALLOW getMonthlyRERCount / loadRERStatus own query", () => assertSucceeds(getDocs(query(collection(db(ALICE), "expert_reviews"), where("requesterUid", "==", "alice"), where("monthKey", "==", "2026-10")))));
test("ALLOW checkRERNotification own query", () => assertSucceeds(getDocs(query(collection(db(BOB), "expert_reviews"), where("requesterUid", "==", "bob"), where("status", "==", "responded")))));
test("ALLOW expert loadExpertPanel lists all", () => assertSucceeds(getDocs(collection(db(EXPERT), "expert_reviews"))));
test("ALLOW expert archive query", () => assertSucceeds(getDocs(query(collection(db(EXPERT), "expert_reviews"), where("status", "==", "responded")))));
test("ALLOW expert submitExpertResponse: review status + feed post", async () => {
  await assertSucceeds(updateDoc(doc(db(EXPERT), "expert_reviews/erAlice"), { status: "responded", responseText: "r", respondedAt: 2 }));
  await assertSucceeds(addDoc(collection(db(EXPERT), "posts"), { author: "Malik", authorUid: "expert", type: "expert-response", reviewId: "erAlice", requesterUid: "alice", requesterName: "Alice", pageUrl: "https://a.com", body: "r", replies: [], props: [], propsCount: 0, timestamp: 1 }));
});
test("ALLOW expert saveExpertResponseEdit: post body + review text", async () => {
  await assertSucceeds(updateDoc(doc(db(EXPERT), "posts/respExpert"), { body: "edited" }));
  await assertSucceeds(updateDoc(doc(db(EXPERT), "expert_reviews/erBob"), { responseText: "edited" }));
});
test("ALLOW admin reads all reviews (runDuplicateOverCapCheck)", () => assertSucceeds(getDocs(collection(db(ADMIN), "expert_reviews"))));
test("DENY member lists all reviews", () => assertFails(getDocs(collection(db(ALICE), "expert_reviews"))));
test("DENY member reads another's review", () => assertFails(getDoc(doc(db(ALICE), "expert_reviews/erBob"))));
test("DENY member responds to own review", () => assertFails(updateDoc(doc(db(ALICE), "expert_reviews/erAlice"), { status: "responded", responseText: "self" })));
test("DENY member deletes a review", () => assertFails(deleteDoc(doc(db(ALICE), "expert_reviews/erAlice"))));
test("DENY request filed as someone else", () => assertFails(addDoc(collection(db(ALICE), "expert_reviews"), { requesterUid: "bob", status: "pending" })));
test("DENY request pre-marked responded", () => assertFails(addDoc(collection(db(ALICE), "expert_reviews"), { requesterUid: "alice", status: "responded", responseText: "fake" })));
test("DENY expert changes requester fields", () => assertFails(updateDoc(doc(db(EXPERT), "expert_reviews/erAlice"), { requesterUid: "bob" })));

// ── Backlinks ─────────────────────────────────────────────
test("ALLOW saveListing own", () => assertSucceeds(setDoc(doc(db(ALICE), "wac_backlinks/alice"), { uid: "alice", displayName: "Alice", siteUrl: "https://a.com", siteNiche: "n", siteDescription: "d", exchangeType: "guest", contactEmail: "a@x.com", listedAt: new Date(), isActive: true })));
test("ALLOW removeListing own", async () => {
  await env.withSecurityRulesDisabled((c) => setDoc(doc(c.firestore(), "wac_backlinks/alice"), { uid: "alice" }));
  await assertSucceeds(deleteDoc(doc(db(ALICE), "wac_backlinks/alice")));
});
test("ALLOW member browses backlinks", () => assertSucceeds(getDocs(collection(db(ALICE), "wac_backlinks"))));
test("ALLOW admin adminDeleteBacklink", () => assertSucceeds(deleteDoc(doc(db(ADMIN), "wac_backlinks/bob"))));
test("DENY overwrite someone else's listing", () => assertFails(setDoc(doc(db(ALICE), "wac_backlinks/bob"), { uid: "alice", siteUrl: "https://evil.com" })));
test("DENY delete someone else's listing", () => assertFails(deleteDoc(doc(db(ALICE), "wac_backlinks/bob"))));
test("DENY extra fields on listing", () => assertFails(setDoc(doc(db(ALICE), "wac_backlinks/alice"), { uid: "alice", siteUrl: "https://a.com", isPro: true })));

// ── Coworking ─────────────────────────────────────────────
test("ALLOW member reads sessions + visibility", async () => {
  await assertSucceeds(getDoc(doc(db(ALICE), "wac_coworking_sessions/_visibility")));
  await assertSucceeds(getDocs(query(collection(db(ALICE), "wac_coworking_sessions"), where("active", "==", true))));
});
test("ALLOW rsvpCowork own", () => assertSucceeds(setDoc(doc(db(ALICE), "wac_coworking_sessions/s1/rsvps/alice"), { uid: "alice", name: "Alice", rsvpAt: 1 })));
test("ALLOW admin session CRUD + visibility + attendance", async () => {
  await assertSucceeds(addDoc(collection(db(ADMIN), "wac_coworking_sessions"), { label: "x", calendarUrl: "", active: true, createdAt: 1 }));
  await assertSucceeds(setDoc(doc(db(ADMIN), "wac_coworking_sessions/_visibility"), { visible: false }));
  await assertSucceeds(updateDoc(doc(db(ADMIN), "wac_coworking_sessions/s1"), { active: false }));
  await assertSucceeds(setDoc(doc(db(ADMIN), "wac_coworking_sessions/s1/attendees/alice"), { uid: "alice", awardedAt: 1 }));
  await assertSucceeds(deleteDoc(doc(db(ADMIN), "wac_coworking_sessions/s1")));
});
test("DENY member edits session calendar link", () => assertFails(updateDoc(doc(db(ALICE), "wac_coworking_sessions/s1"), { calendarUrl: "https://evil.com" })));
test("DENY member flips visibility", () => assertFails(setDoc(doc(db(ALICE), "wac_coworking_sessions/_visibility"), { visible: false })));
test("DENY RSVP for someone else", () => assertFails(setDoc(doc(db(ALICE), "wac_coworking_sessions/s1/rsvps/bob"), { uid: "bob", name: "Bob", rsvpAt: 1 })));
test("DENY self-award attendance", () => assertFails(setDoc(doc(db(ALICE), "wac_coworking_sessions/s1/attendees/alice"), { uid: "alice", awardedAt: 1 })));

// ── Reports ───────────────────────────────────────────────
test("ALLOW submitBugReport", () => assertSucceeds(addDoc(collection(db(ALICE), "bug_reports"), { name: "Alice", email: "alice@x.com", uid: "alice", message: "m", screenshot: null, resolved: false, ts: 1 })));
test("ALLOW logPlatformError", () => assertSucceeds(addDoc(collection(db(ALICE), "platform_errors"), { context: "c", message: "m", timestamp: 1, reportedBy: "alice@x.com" })));
test("ALLOW admin loadBugReports / toggle / delete", async () => {
  await assertSucceeds(getDocs(collection(db(ADMIN), "bug_reports")));
  await assertSucceeds(updateDoc(doc(db(ADMIN), "bug_reports/b1"), { resolved: true }));
  await assertSucceeds(deleteDoc(doc(db(ADMIN), "bug_reports/b1")));
});
test("DENY member reads bug reports / errors", async () => {
  await assertFails(getDocs(collection(db(ALICE), "bug_reports")));
  await assertFails(getDocs(collection(db(ALICE), "platform_errors")));
});
test("DENY bug report filed as someone else", () => assertFails(addDoc(collection(db(ALICE), "bug_reports"), { uid: "bob", message: "m" })));

// ── Admin-only content ────────────────────────────────────
test("ALLOW member reads announcements/resources/archives", async () => {
  await assertSucceeds(getDocs(collection(db(ALICE), "announcements")));
  await assertSucceeds(getDocs(collection(db(ALICE), "resources")));
  await assertSucceeds(getDocs(collection(db(ALICE), "wac_round_archives")));
});
test("ALLOW admin submitAnnouncement / submitResource / archiveRound", async () => {
  await assertSucceeds(addDoc(collection(db(ADMIN), "announcements"), { title: "t", body: "b", timestamp: 1 }));
  await assertSucceeds(addDoc(collection(db(ADMIN), "resources"), { title: "t", url: "https://x.com", timestamp: 1 }));
  await assertSucceeds(setDoc(doc(db(ADMIN), "wac_round_archives/R2_alice"), { uid: "alice", points: 50, round: "R2" }));
});
test("DENY member writes announcement/resource/archive", async () => {
  await assertFails(addDoc(collection(db(ALICE), "announcements"), { title: "fake" }));
  await assertFails(updateDoc(doc(db(ALICE), "resources/r1"), { url: "https://evil.com" }));
  await assertFails(setDoc(doc(db(ALICE), "wac_round_archives/R2_alice"), { points: 9999 }));
});

// ── WAC Pro archives ──────────────────────────────────────
test("ALLOW owner reads own Pro archives", async () => {
  await assertSucceeds(getDoc(doc(db(BOB), "wac_action_plan_memory/bob")));
  await assertSucceeds(getDoc(doc(db(BOB), "wac_copy_assist/bob")));
  await assertSucceeds(getDoc(doc(db(BOB), "wac_seo_analysis/bob")));
});
test("DENY read another's Pro archives", async () => {
  await assertFails(getDoc(doc(db(ALICE), "wac_action_plan_memory/bob")));
  await assertFails(getDoc(doc(db(ALICE), "wac_copy_assist/bob")));
});
test("DENY client writes Pro archives (functions only)", async () => {
  await assertFails(setDoc(doc(db(BOB), "wac_action_plan_memory/bob"), { items: [] }));
  await assertFails(setDoc(doc(db(BOB), "wac_seo_analysis/bob"), { lastUploadMonth: null }));
});
