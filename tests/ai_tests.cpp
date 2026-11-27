/**
 * @file   ai_tests.cpp
 * @brief  Recommendation, context, and AI approval tests (NG-042..NG-046).
 */

#include "testharness.h"
#include "testdeclarations.h"

// ─── NG-042: deterministic recommendation engine ────────────────────────────
// Every recommendation is advice: it carries evidence, confidence, an expected
// effect, and a reversal action, and nothing is ever applied automatically.
void testRecommendationEngine()
{
    ActivityClassifier classifier;
    RecommendationEngine engine;

    auto contextFor = [&classifier](const QString &executableName) {
        RecommendationContext context;
        context.observation.executableName = executableName;
        context.observation.executablePath = QStringLiteral("C:/Apps/") + executableName;
        context.activity = classifier.classify(context.observation);
        return context;
    };

    // Background updates are throttled, with a rate derived from what was seen.
    RecommendationContext chrome = contextFor(QStringLiteral("updater.exe"));
    chrome.observation.publisher = QStringLiteral("Google LLC");
    chrome.observation.product = QStringLiteral("Google Update");
    chrome.activity = classifier.classify(chrome.observation);
    chrome.bytesPerSecond = 4ULL * 1024ULL * 1024ULL;
    const Recommendation throttle = engine.recommend(chrome);
    check(throttle.action == RecommendationAction::Throttle,
          QStringLiteral("a browser updater is throttled"));
    check(throttle.hasSuggestedPolicy(),
          QStringLiteral("a throttle recommendation offers a policy seed"));
    checkEqual(static_cast<int>(throttle.suggestedPolicy.action), static_cast<int>(NetworkPolicy::Action::Throttle),
               QStringLiteral("the seed is a throttle policy"));
    checkEqual(throttle.suggestedPolicy.rateBitsPerSecond,
               static_cast<quint64>(2ULL * 1024ULL * 1024ULL * 8ULL),
               QStringLiteral("the seed uses half the observed rate"));
    check(throttle.expectedEffect.contains(QStringLiteral("2.0 MiB/s")),
          QStringLiteral("the expected effect states the suggested rate"));
    check(throttle.requiresUserApproval && !throttle.enforcesAnything(),
          QStringLiteral("a recommendation never enforces itself"));
    checkEqual(throttle.confidenceName(),
               QStringLiteral("Likely"),
               QStringLiteral("the recommendation carries the activity confidence"));
    check(!throttle.evidence.isEmpty() &&
              throttle.evidence.join(QStringLiteral(" ")).contains(
                  QStringLiteral("builtin-chrome-update")),
          QStringLiteral("the recommendation carries the matched-rule evidence"));
    check(!throttle.whatObserved.isEmpty() && !throttle.whyLikely.isEmpty(),
          QStringLiteral("a recommendation says what it saw and why"));
    check(!throttle.reversalAction.trimmed().isEmpty(),
          QStringLiteral("a recommendation says how to reverse it"));
    check(throttle.lines().join(QStringLiteral("\n")).contains(QStringLiteral("To reverse:")),
          QStringLiteral("the text form includes the reversal action"));

    RecommendationContext windowsUpdate;
    windowsUpdate.observation.serviceName = QStringLiteral("wuauserv");
    windowsUpdate.observation.service = true;
    windowsUpdate.activity = classifier.classify(windowsUpdate.observation);
    const Recommendation serviceThrottle = engine.recommend(windowsUpdate);
    check(serviceThrottle.action == RecommendationAction::Throttle,
          QStringLiteral("a Windows Update service is throttled"));
    checkEqual(serviceThrottle.suggestedPolicy.scope, QStringLiteral("service"),
               QStringLiteral("an unpathed service is scoped by service"));

    RecommendationContext oneDrive = contextFor(QStringLiteral("OneDrive.exe"));
    oneDrive.observation.publisher = QStringLiteral("Microsoft Corporation");
    oneDrive.observation.product = QStringLiteral("Microsoft OneDrive");
    oneDrive.activity = classifier.classify(oneDrive.observation);
    const Recommendation schedule = engine.recommend(oneDrive);
    check(schedule.action == RecommendationAction::Schedule,
          QStringLiteral("cloud sync is scheduled rather than throttled"));
    checkEqual(static_cast<int>(schedule.suggestedPolicy.action), static_cast<int>(NetworkPolicy::Action::Schedule),
               QStringLiteral("the seed is a schedule policy"));
    checkEqual(schedule.suggestedPolicy.schedule, QStringLiteral("overnight"),
               QStringLiteral("the schedule uses the overnight window"));
    check(schedule.suggestedPolicy.scheduleType == NetworkPolicy::ScheduleType::Recurring,
          QStringLiteral("the schedule is recurring"));

    const Recommendation pause = engine.recommend(contextFor(QStringLiteral("steam.exe")));
    check(pause.action == RecommendationAction::Pause,
          QStringLiteral("a game launcher is paused during play"));
    check(pause.suggestedPolicy.action == NetworkPolicy::Action::Block,
          QStringLiteral("pausing is a temporary block"));
    check(pause.suggestedPolicy.expiration.isValid(),
          QStringLiteral("the temporary block has an expiration"));
    check(pause.reversalAction.contains(QStringLiteral("Policies")),
          QStringLiteral("the reversal points at the policy list"));

    const Recommendation developer =
        engine.recommend(contextFor(QStringLiteral("code.exe")));
    check(developer.action == RecommendationAction::ReviewSettings,
          QStringLiteral("a developer tool is suggested for review"));
    check(!developer.hasSuggestedPolicy(),
          QStringLiteral("a review recommendation offers no policy"));
    check(developer.expectedEffect.contains(QStringLiteral("Nothing is limited")),
          QStringLiteral("a review recommendation says nothing changes"));

    RecommendationContext npm;
    npm.observation.domain = QStringLiteral("registry.npmjs.org");
    npm.activity = classifier.classify(npm.observation);
    check(engine.recommend(npm).action == RecommendationAction::Throttle,
          QStringLiteral("a package registry download is throttled"));

    RecommendationContext call;
    call.observation.executableName = QStringLiteral("zoom.exe");
    call.activity = classifier.classify(call.observation);
    check(engine.recommend(call).action == RecommendationAction::NoAction,
          QStringLiteral("a call is never throttled"));

    RecommendationContext stream;
    stream.observation.executableName = QStringLiteral("spotify.exe");
    stream.activity = classifier.classify(stream.observation);
    check(engine.recommend(stream).action == RecommendationAction::NoAction,
          QStringLiteral("a stream is never throttled"));

    RecommendationContext defender;
    defender.observation.executableName = QStringLiteral("MsMpEng.exe");
    defender.activity = classifier.classify(defender.observation);
    check(engine.recommend(defender).action == RecommendationAction::Throttle,
          QStringLiteral("a virus definition update is throttled"));

    // Foreground transfers are left alone (or reviewed on a metered link).
    RecommendationContext download = contextFor(QStringLiteral("browser.exe"));
    download.observation.foreground = true;
    download.observation.bytesPerSecond = 2ULL * 1024ULL * 1024ULL;
    download.foreground = true;
    download.bytesPerSecond = download.observation.bytesPerSecond;
    download.activity = classifier.classify(download.observation);
    const Recommendation noAction = engine.recommend(download);
    check(noAction.action == RecommendationAction::NoAction,
          QStringLiteral("a foreground download gets a no-action recommendation"));
    check(!noAction.hasSuggestedPolicy(),
          QStringLiteral("no-action recommendations carry no policy"));

    download.meteredConnection = true;
    check(engine.recommend(download).action == RecommendationAction::ReviewSettings,
          QStringLiteral("a foreground download on a metered link is reviewed"));

    // A foreground activity that would otherwise be throttled becomes a review.
    RecommendationContext foregroundUpdate = chrome;
    foregroundUpdate.foreground = true;
    check(engine.recommend(foregroundUpdate).action == RecommendationAction::ReviewSettings,
          QStringLiteral("a foreground updater is not throttled silently"));

    // Unknown activity is reviewable and still policy-creatable.
    const Recommendation unknown =
        engine.recommend(contextFor(QStringLiteral("notes.exe")));
    check(unknown.action == RecommendationAction::ReviewSettings,
          QStringLiteral("unknown activity is suggested for review"));
    check(unknown.category == CatalogCategory::Unknown,
          QStringLiteral("an unknown recommendation keeps the unknown category"));
    check(unknown.evidence.join(QStringLiteral(" ")).contains(
              QStringLiteral("No local rule matched")),
          QStringLiteral("unknown activity keeps its explanation"));
    checkEqual(unknown.confidenceName(), QStringLiteral("Unknown"),
               QStringLiteral("unknown activity keeps unknown confidence"));

    // An explicit user decision is never second-guessed.
    RecommendationContext covered = chrome;
    covered.explicitPolicyCovers = true;
    const Recommendation coveredResult = engine.recommend(covered);
    check(coveredResult.action == RecommendationAction::NoAction,
          QStringLiteral("an existing policy suppresses the recommendation"));
    check(!coveredResult.hasSuggestedPolicy(),
          QStringLiteral("an existing policy produces no new policy seed"));
    checkEqual(coveredResult.title, QStringLiteral("Already covered by your policy"),
               QStringLiteral("the suppressed recommendation says why"));

    RecommendationContext exempted = chrome;
    exempted.exempt = true;
    const Recommendation exemptResult = engine.recommend(exempted);
    check(exemptResult.action == RecommendationAction::NoAction,
          QStringLiteral("an exemption suppresses the recommendation"));
    checkEqual(exemptResult.title, QStringLiteral("This app is exempt"),
               QStringLiteral("the exempt recommendation says why"));

    checkEqual(static_cast<int>(RecommendationEngine::recommendedActionFor(CatalogCategory::CloudSync)),
               static_cast<int>(RecommendationAction::Schedule),
               QStringLiteral("the category mapping is deterministic for cloud sync"));
    checkEqual(static_cast<int>(RecommendationEngine::recommendedActionFor(CatalogCategory::Unknown)),
               static_cast<int>(RecommendationAction::ReviewSettings),
               QStringLiteral("the category mapping is deterministic for unknown activity"));

    checkEqual(RecommendationEngine::suggestedRateBitsPerSecond(0),
               static_cast<quint64>(1024ULL * 1024ULL * 8ULL),
               QStringLiteral("an unknown rate uses a 1 MiB/s suggestion"));
    checkEqual(RecommendationEngine::suggestedRateBitsPerSecond(1024),
               static_cast<quint64>(256ULL * 1024ULL * 8ULL),
               QStringLiteral("a small rate is clamped up to 256 KiB/s"));
    checkEqual(RecommendationEngine::suggestedRateBitsPerSecond(100ULL * 1024ULL * 1024ULL),
               static_cast<quint64>(4ULL * 1024ULL * 1024ULL * 8ULL),
               QStringLiteral("a large rate is clamped down to 4 MiB/s"));

    checkEqual(recommendationActionToken(RecommendationAction::Throttle),
               QStringLiteral("throttle"),
               QStringLiteral("the action has a stable token"));
    checkEqual(recommendationActionDisplayName(RecommendationAction::ReviewSettings),
               QStringLiteral("Review settings"),
               QStringLiteral("the action has a plain label"));
}

// ─── NG-043: local recommendation feedback ──────────────────────────────────
// Feedback is remembered on this device only and changes future suggestions:
// "incorrect" downgrades an actionable suggestion to a review, "unwanted" hides
// it, and neither ever overrides an explicit policy or exemption.
void testRecommendationFeedback()
{
    checkEqual(recommendationFeedbackToken(RecommendationFeedback::Useful),
               QStringLiteral("useful"),
               QStringLiteral("useful feedback has a stable token"));
    checkEqual(recommendationFeedbackToken(RecommendationFeedback::Incorrect),
               QStringLiteral("incorrect"),
               QStringLiteral("incorrect feedback has a stable token"));
    checkEqual(recommendationFeedbackToken(RecommendationFeedback::Unwanted),
               QStringLiteral("unwanted"),
               QStringLiteral("unwanted feedback has a stable token"));
    checkEqual(recommendationFeedbackDisplayName(RecommendationFeedback::Unwanted),
               QStringLiteral("Not wanted"),
               QStringLiteral("unwanted feedback has a plain label"));

    RecommendationFeedback parsed = RecommendationFeedback::None;
    check(recommendationFeedbackFromToken(QStringLiteral("incorrect"), &parsed)
              && parsed == RecommendationFeedback::Incorrect,
          QStringLiteral("a feedback token parses back"));
    check(!recommendationFeedbackFromToken(QStringLiteral("bogus"), &parsed),
          QStringLiteral("an unknown feedback token is rejected"));

    ActivityClassifier classifier;
    RecommendationEngine engine;
    RecommendationFeedbackStore store;
    store.clear();
    engine.setFeedbackStore(&store);

    auto contextFor = [&classifier](const QString &executableName) {
        RecommendationContext context;
        context.observation.executableName = executableName;
        context.observation.executablePath =
            QStringLiteral("C:/Apps/") + executableName;
        context.activity = classifier.classify(context.observation);
        return context;
    };

    RecommendationContext chrome = contextFor(QStringLiteral("updater.exe"));
    chrome.observation.publisher = QStringLiteral("Google LLC");
    chrome.observation.product = QStringLiteral("Google Update");
    chrome.activity = classifier.classify(chrome.observation);
    chrome.bytesPerSecond = 4ULL * 1024ULL * 1024ULL;

    const Recommendation baseline = engine.recommend(chrome);
    check(baseline.action == RecommendationAction::Throttle,
          QStringLiteral("the baseline updater suggestion is a throttle"));
    const QString key = baseline.feedbackKey;
    check(!key.isEmpty(),
          QStringLiteral("a recommendation carries its local feedback key"));
    checkEqual(key, RecommendationEngine::feedbackKeyFor(chrome),
               QStringLiteral("the key is deterministic for the same evidence"));

    // The durable identity makes the key survive an update or a moved install.
    RecommendationContext moved = chrome;
    moved.observation.identityId = QStringLiteral("sha1-identity");
    const QString identityKey = RecommendationEngine::feedbackKeyFor(moved);
    moved.observation.executablePath = QStringLiteral("D:/Elsewhere/updater.exe");
    checkEqual(RecommendationEngine::feedbackKeyFor(moved), identityKey,
               QStringLiteral("the identity keeps the feedback key stable"));

    // A different category and a different application are different keys.
    RecommendationContext sync = contextFor(QStringLiteral("OneDrive.exe"));
    sync.observation.publisher = QStringLiteral("Microsoft Corporation");
    sync.observation.product = QStringLiteral("Microsoft OneDrive");
    sync.activity = classifier.classify(sync.observation);
    check(RecommendationEngine::feedbackKeyFor(sync) != key,
          QStringLiteral("a different application has a different key"));
    check(engine.recommend(sync).action == RecommendationAction::Schedule,
          QStringLiteral("feedback for one application leaves another alone"));

    // A verdict persists across a fresh store instance.
    check(store.setFeedback(key, RecommendationFeedback::Useful),
          QStringLiteral("feedback saves without a store error"));
    check(store.feedbackFor(key) == RecommendationFeedback::Useful,
          QStringLiteral("feedback reads back immediately"));
    checkEqual(store.count(), 1, QStringLiteral("one verdict is stored"));
    {
        RecommendationFeedbackStore reloaded;
        check(reloaded.feedbackFor(key) == RecommendationFeedback::Useful,
              QStringLiteral("feedback persists across a store reload"));
    }

    check(store.setFeedback(key, RecommendationFeedback::Incorrect),
          QStringLiteral("a verdict can be replaced"));
    {
        RecommendationFeedbackStore reloaded;
        check(reloaded.feedbackFor(key) == RecommendationFeedback::Incorrect,
              QStringLiteral("the replacement persists"));
    }

    // "Incorrect" keeps the activity visible but downgrades an actionable
    // suggestion to a review, and offers no policy seed.
    const Recommendation incorrect = engine.recommend(chrome);
    check(incorrect.action == RecommendationAction::ReviewSettings,
          QStringLiteral("an incorrect suggestion is downgraded to a review"));
    check(incorrect.feedbackApplied,
          QStringLiteral("the recommendation reports that feedback applied"));
    check(incorrect.feedback == RecommendationFeedback::Incorrect,
          QStringLiteral("the recommendation carries the recorded verdict"));
    check(!incorrect.hasSuggestedPolicy(),
          QStringLiteral("a downgraded suggestion offers no policy seed"));
    check(incorrect.whyLikely.contains(QStringLiteral("incorrect")),
          QStringLiteral("the downgraded suggestion explains the verdict"));

    // "Unwanted" hides the suggestion entirely.
    check(store.setFeedback(key, RecommendationFeedback::Unwanted),
          QStringLiteral("the unwanted verdict saves"));
    const Recommendation unwanted = engine.recommend(chrome);
    check(unwanted.action == RecommendationAction::NoAction,
          QStringLiteral("an unwanted suggestion is hidden"));
    check(unwanted.feedbackApplied,
          QStringLiteral("the hidden suggestion reports that feedback applied"));
    check(!unwanted.hasSuggestedPolicy(),
          QStringLiteral("a hidden suggestion offers no policy seed"));
    checkEqual(unwanted.title, QStringLiteral("Suggestion hidden"),
               QStringLiteral("the hidden suggestion says so"));
    check(unwanted.reversalAction.contains(QStringLiteral("feedback")),
          QStringLiteral("the hidden suggestion says how to bring it back"));

    // "Useful" leaves the suggestion in place.
    check(store.setFeedback(key, RecommendationFeedback::Useful),
          QStringLiteral("the useful verdict saves"));
    const Recommendation useful = engine.recommend(chrome);
    check(useful.action == RecommendationAction::Throttle,
          QStringLiteral("a useful suggestion stays a throttle"));
    check(useful.feedback == RecommendationFeedback::Useful,
          QStringLiteral("the useful verdict is carried"));
    check(!useful.feedbackApplied,
          QStringLiteral("a useful verdict does not change the outcome"));
    check(useful.whyLikely.contains(QStringLiteral("useful")),
          QStringLiteral("the suggestion acknowledges the useful verdict"));

    // An explicit policy and an exemption always win over feedback.
    RecommendationContext covered = chrome;
    covered.explicitPolicyCovers = true;
    const Recommendation coveredResult = engine.recommend(covered);
    check(coveredResult.action == RecommendationAction::NoAction,
          QStringLiteral("an explicit policy still suppresses the suggestion"));
    checkEqual(coveredResult.title, QStringLiteral("Already covered by your policy"),
               QStringLiteral("the explicit policy keeps its explanation"));
    check(!coveredResult.feedbackApplied && coveredResult.feedbackKey.isEmpty(),
          QStringLiteral("feedback is not consulted when a policy already covers the app"));

    RecommendationContext exempted = chrome;
    exempted.exempt = true;
    const Recommendation exemptResult = engine.recommend(exempted);
    check(exemptResult.action == RecommendationAction::NoAction,
          QStringLiteral("an exemption still suppresses the suggestion"));
    checkEqual(exemptResult.title, QStringLiteral("This app is exempt"),
               QStringLiteral("the exemption keeps its explanation"));

    // Clearing the verdict restores the suggestion.
    check(store.setFeedback(key, RecommendationFeedback::None),
          QStringLiteral("clearing one verdict succeeds"));
    check(store.feedbackFor(key) == RecommendationFeedback::None,
          QStringLiteral("the cleared verdict is gone"));
    check(engine.recommend(chrome).action == RecommendationAction::Throttle,
          QStringLiteral("clearing feedback restores the suggestion"));

    // The serialised form is versioned and carries no activity data.
    RecommendationFeedbackEntry entry;
    entry.key = QStringLiteral("browser-update|id:abc");
    entry.feedback = RecommendationFeedback::Useful;
    entry.updatedAt = QDateTime::currentDateTimeUtc();
    const QString json = RecommendationFeedbackStore::toJson({entry});
    checkEqual(objectOf(json).value(QStringLiteral("schemaVersion")).toInt(),
               RecommendationFeedbackStore::kSchemaVersion,
               QStringLiteral("the feedback payload is versioned"));
    bool ok = false;
    const QList<RecommendationFeedbackEntry> roundTrip =
        RecommendationFeedbackStore::fromJson(json, &ok);
    check(ok && roundTrip.size() == 1
              && roundTrip.first().feedback == RecommendationFeedback::Useful,
          QStringLiteral("a feedback payload round-trips"));
    check(!json.contains(QStringLiteral("bytesPerSecond"))
              && !json.contains(QStringLiteral("example.com"))
              && !json.contains(QStringLiteral("remoteAddress")),
          QStringLiteral("feedback stores only the key, verdict, and time"));

    QJsonObject newer = objectOf(json);
    newer[QStringLiteral("schemaVersion")] =
        RecommendationFeedbackStore::kSchemaVersion + 1;
    ok = true;
    check(RecommendationFeedbackStore::fromJson(
              QString::fromUtf8(QJsonDocument(newer).toJson(QJsonDocument::Compact)),
              &ok).isEmpty() && !ok,
          QStringLiteral("a newer feedback schema is rejected as a whole"));

    ok = true;
    RecommendationFeedbackStore::fromJson(QStringLiteral("not json"), &ok);
    check(!ok, QStringLiteral("a malformed feedback payload is rejected"));

    ok = false;
    const QString unknownToken = QStringLiteral(
        "{\"schemaVersion\":1,\"entries\":[{\"key\":\"k\",\"feedback\":\"maybe\"}]}");
    check(RecommendationFeedbackStore::fromJson(unknownToken, &ok).isEmpty() && ok,
          QStringLiteral("an unknown verdict is skipped rather than guessed"));

    // Loading is bounded, keeping the most recent verdicts.
    QJsonArray many;
    const int overBound = RecommendationFeedbackStore::kMaxEntries + 50;
    for (int i = 0; i < overBound; ++i) {
        QJsonObject object;
        object[QStringLiteral("key")] = QStringLiteral("key-%1").arg(i);
        object[QStringLiteral("feedback")] = QStringLiteral("useful");
        object[QStringLiteral("updatedAt")] = QDateTime::currentDateTimeUtc()
            .addSecs(i).toString(Qt::ISODate);
        many.append(object);
    }
    QJsonObject boundedRoot;
    boundedRoot[QStringLiteral("schemaVersion")] = 1;
    boundedRoot[QStringLiteral("entries")] = many;
    ok = false;
    checkEqual(static_cast<int>(RecommendationFeedbackStore::fromJson(
                   QString::fromUtf8(QJsonDocument(boundedRoot).toJson(QJsonDocument::Compact)),
                   &ok).size()),
               RecommendationFeedbackStore::kMaxEntries,
               QStringLiteral("feedback loading is bounded"));

    check(store.clear(), QStringLiteral("clearing all feedback succeeds"));
    checkEqual(store.count(), 0, QStringLiteral("no verdict remains after clear"));
    QSettings().clear();
}

// ─── NG-044: structured AI context ─────────────────────────────────────────
// The context is metadata only, names every field it does not know, is bounded
// to a fixed payload size, and can be reviewed before anything is sent.
void testAiContext()
{
    auto arrayHas = [](const QJsonArray &array, const QString &text) {
        for (const QJsonValue &value : array) {
            if (value.toString() == text) return true;
        }
        return false;
    };

    ActivityClassifier classifier;
    RecommendationEngine engine;
    RecommendationFeedbackStore store;
    store.clear();
    engine.setFeedbackStore(&store);

    RecommendationContext context;
    context.observation.identityId = QStringLiteral("sha1-4f2a");
    context.observation.displayName = QStringLiteral("Google Update");
    context.observation.executableName = QStringLiteral("updater.exe");
    context.observation.executablePath =
        QStringLiteral("C:/Users/alice/AppData/Local/Google/updater.exe");
    context.observation.publisher = QStringLiteral("Google LLC");
    context.observation.product = QStringLiteral("Google Update");
    context.observation.publisherVerified = true;
    context.observation.serviceName = QStringLiteral("gupdate");
    context.observation.groupName = QStringLiteral("Google");
    context.observation.domain = QStringLiteral("update.googleapis.com");
    context.observation.remoteAddress = QStringLiteral("142.250.1.2");
    context.activity = classifier.classify(context.observation);
    context.bytesPerSecond = 4ULL * 1024ULL * 1024ULL;
    context.foreground = false;
    context.meteredConnection = true;

    const Recommendation recommendation = engine.recommend(context);
    check(recommendation.action == RecommendationAction::Throttle,
          QStringLiteral("the fixture activity still recommends a throttle"));
    check(recommendation.hasSuggestedPolicy(),
          QStringLiteral("the fixture recommendation offers a policy seed"));

    const AiContext ai = AiContext::forRecommendation(context, recommendation);
    check(!ai.isEmpty(), QStringLiteral("a context is built from a recommendation"));

    const QString json = ai.toJson();
    const QJsonObject root = objectOf(json);
    checkEqual(root.value(QStringLiteral("schemaVersion")).toInt(),
               AiContext::kSchemaVersion,
               QStringLiteral("the AI context is versioned"));
    checkEqual(root.value(QStringLiteral("format")).toString(),
               AiContext::formatToken(),
               QStringLiteral("the AI context carries a stable format marker"));
    check(root.value(QStringLiteral("generatedAt")).toString().endsWith('Z'),
          QStringLiteral("the context records when it was generated"));

    const QJsonObject identity = root.value(QStringLiteral("identity")).toObject();
    checkEqual(identity.value(QStringLiteral("executable")).toString(),
               QStringLiteral("updater.exe"),
               QStringLiteral("only the executable base name is sent"));
    checkEqual(identity.value(QStringLiteral("publisher")).toString(),
               QStringLiteral("Google LLC"),
               QStringLiteral("the publisher metadata is metadata, not a destination"));

    const QJsonObject classification =
        root.value(QStringLiteral("classification")).toObject();
    checkEqual(classification.value(QStringLiteral("category")).toString(),
               QStringLiteral("browser-update"),
               QStringLiteral("the classification token is carried"));
    checkEqual(classification.value(QStringLiteral("confidenceIsCertain")).toBool(),
               false, QStringLiteral("a strong inference is not presented as a fact"));
    check(!classification.value(QStringLiteral("rules")).toArray().isEmpty(),
          QStringLiteral("the matched local rules are carried as evidence"));

    const QJsonObject activity = root.value(QStringLiteral("activity")).toObject();
    checkEqual(activity.value(QStringLiteral("destination")).toString(),
               QStringLiteral("***.com"),
               QStringLiteral("the destination keeps only its top-level label"));
    checkEqual(static_cast<quint64>(
                   activity.value(QStringLiteral("bytesPerSecond")).toDouble()),
               context.bytesPerSecond,
               QStringLiteral("only the aggregate rate is carried"));
    checkEqual(activity.value(QStringLiteral("metered")).toBool(), true,
               QStringLiteral("the metered session fact is carried"));

    const QJsonObject recommendationJson =
        root.value(QStringLiteral("recommendation")).toObject();
    checkEqual(recommendationJson.value(QStringLiteral("action")).toString(),
               QStringLiteral("throttle"),
               QStringLiteral("the recommended action token is carried"));
    checkEqual(recommendationJson.value(QStringLiteral("policyScope")).toString(),
               recommendation.suggestedPolicy.scope,
               QStringLiteral("only the policy scope token is sent"));

    // Nothing that identifies where the user went, or where the app lives, is
    // in the payload.
    check(!json.contains(QStringLiteral("update.googleapis.com"))
              && !json.contains(QStringLiteral("142.250.1.2")),
          QStringLiteral("the context carries no raw destination or address"));
    check(!json.contains(QStringLiteral("C:/Users"))
              && !json.contains(QStringLiteral("targetId")),
          QStringLiteral("the context carries no path or policy target id"));

    // A field the caller cannot supply is named, not silently empty.
    AiContext sparse;
    sparse.executableName = QStringLiteral("tool.exe");
    const QStringList unknown = sparse.unknownFields();
    check(unknown.contains(QStringLiteral("identity.publisher"))
              && unknown.contains(QStringLiteral("activity.destination"))
              && unknown.contains(QStringLiteral("recommendation.policyScope")),
          QStringLiteral("the schema names the fields it does not know"));
    check(!unknown.contains(QStringLiteral("identity.executable")),
          QStringLiteral("a supplied field is not listed as unknown"));
    const QJsonObject sparseRoot = objectOf(sparse.toJson());
    check(arrayHas(sparseRoot.value(QStringLiteral("unknown")).toArray(),
                   QStringLiteral("identity.publisher")),
          QStringLiteral("the payload serialises its unknown fields"));
    check(!sparse.toJson().contains(QStringLiteral("publisherVerified")),
          QStringLiteral("an unknown publisher is not guessed to be verified"));

    // Free text is redacted and cannot smuggle a second line into the payload.
    AiContext leaky;
    leaky.displayName = QStringLiteral("Evil\nName");
    leaky.evidence << QStringLiteral("contacted update.googleapis.com from 142.250.1.2");
    const QString leakyJson = leaky.toJson();
    check(!leakyJson.contains(QStringLiteral("update.googleapis.com"))
              && !leakyJson.contains(QStringLiteral("142.250.1.2")),
          QStringLiteral("free-text evidence is redacted too"));
    check(!leakyJson.contains(QStringLiteral("Evil\nName")),
          QStringLiteral("control characters are removed from the payload"));

    // The size limit holds even when every optional field is oversized.
    AiContext huge;
    huge.displayName = QString(8000, QLatin1Char('a'));
    huge.publisher = QString(8000, QLatin1Char('b'));
    huge.serviceName = QString(8000, QLatin1Char('c'));
    huge.groupName = QString(8000, QLatin1Char('d'));
    huge.destination = QString(8000, QLatin1Char('e')) + QStringLiteral(".example.com");
    huge.categoryName = QString(8000, QLatin1Char('f'));
    huge.recommendedAction = QStringLiteral("throttle");
    huge.policyScope = QString(8000, QLatin1Char('g'));
    huge.bytesPerSecond = 123456789; // 117 MiB/s
    for (int i = 0; i < 64; ++i) {
        huge.matchedRuleIds << QString(200, QLatin1Char('r')) + QString::number(i);
        huge.evidence << QString(400, QLatin1Char('e')) + QString::number(i);
    }
    const AiContextPayload bounded = huge.boundedJson();
    check(bounded.fits(), QStringLiteral("a pathological context is bounded"));
    check(bounded.bytes() <= AiContext::kMaxBytes,
          QStringLiteral("the bounded payload respects the byte limit"));
    check(!bounded.truncatedFields.isEmpty(),
          QStringLiteral("a bounded context reports what it shortened"));
    check(bounded.json.contains(QStringLiteral("\"truncated\"")),
          QStringLiteral("the payload records the fields it shortened"));
    check(bounded.json.contains(QStringLiteral("\"unknown\"")),
          QStringLiteral("the payload always records unknown fields"));
    huge.destination.clear();
    huge.evidence.clear();
    huge.matchedRuleIds.clear();
    huge.policyScope.clear();
    huge.publisher.clear();
    huge.serviceName.clear();
    huge.groupName.clear();
    huge.categoryName.clear();
    check(huge.boundedJson().truncatedFields.contains(QStringLiteral("identity.name")),
          QStringLiteral("an over-long value is reported as shortened"));

    // The payload can be read back for inspection.
    bool ok = false;
    const AiContext parsed = AiContext::fromJson(json, &ok);
    check(ok, QStringLiteral("an AI context payload parses back"));
    checkEqual(parsed.categoryToken, QStringLiteral("browser-update"),
               QStringLiteral("the category token round-trips"));
    checkEqual(parsed.destination, QStringLiteral("***.com"),
               QStringLiteral("the redacted destination round-trips"));
    checkEqual(parsed.executableName, QStringLiteral("updater.exe"),
               QStringLiteral("the executable base name round-trips"));
    checkEqual(parsed.bytesPerSecond, context.bytesPerSecond,
               QStringLiteral("the aggregate rate round-trips"));

    // The review text is exactly what a user would inspect before approving.
    const QString preview = ai.previewText();
    check(preview.contains(QStringLiteral("***.com")),
          QStringLiteral("the review shows the redacted destination that would be sent"));
    check(preview.contains(QStringLiteral("Browser update")),
          QStringLiteral("the review names the classification"));
    check(preview.contains(QStringLiteral("Payload:")),
          QStringLiteral("the review states the payload size against the limit"));
    check(!preview.contains(QStringLiteral("update.googleapis.com")),
          QStringLiteral("the review never shows the raw destination"));
    check(preview.contains(QStringLiteral("Not included (unknown):"))
              || ai.unknownFields().isEmpty(),
          QStringLiteral("the review lists the fields the context omits"));
    check(ai.previewLines().size() >= 5,
          QStringLiteral("the review is a line-by-line breakdown"));

    // A newer or foreign document is rejected as a whole.
    QJsonObject newer = root;
    newer[QStringLiteral("schemaVersion")] = AiContext::kSchemaVersion + 1;
    ok = true;
    AiContext::fromJson(
        QString::fromUtf8(QJsonDocument(newer).toJson(QJsonDocument::Compact)), &ok);
    check(!ok, QStringLiteral("a newer AI context schema is rejected"));

    QJsonObject foreign = root;
    foreign[QStringLiteral("format")] = QStringLiteral("oasis.something-else");
    ok = true;
    AiContext::fromJson(
        QString::fromUtf8(QJsonDocument(foreign).toJson(QJsonDocument::Compact)), &ok);
    check(!ok, QStringLiteral("a document with another format is rejected"));

    ok = true;
    AiContext::fromJson(QStringLiteral("not json"), &ok);
    check(!ok, QStringLiteral("a malformed AI context is rejected"));

    store.clear();
    QSettings().clear();
}

// ─── NG-045: optional AI provider adapter ──────────────────────────────────
// AI is off unless configured; the provider only receives the bounded context;
// and every failure returns the unchanged local recommendation.
class FakeAiProvider : public AiProvider
{
public:
    QString name() const override { return QStringLiteral("fake-provider"); }

    AiProviderResponse explain(const AiContextPayload &payload,
                               const AiProviderSettings &settings) override
    {
        ++calls;
        lastPayload = payload.json;
        lastModel = settings.model;
        return response;
    }

    int calls = 0;
    QString lastPayload;
    QString lastModel;
    AiProviderResponse response;
};

void testAiProvider()
{
    QSettings().clear();

    // Off by default, in memory and from an empty store.
    const AiProviderSettings defaults;
    check(!defaults.enabled, QStringLiteral("AI is disabled by default"));
    check(!defaults.isUsable(), QStringLiteral("the default settings cannot be used"));
    check(!AiProviderSettingsStore().load().enabled,
          QStringLiteral("stored settings default to disabled"));

    // The endpoint must be safe before a context could be posted to it.
    AiProviderSettings settings;
    settings.enabled = true;
    settings.model = QStringLiteral("some-model");
    check(!settings.isUsable(),
          QStringLiteral("an enabled provider without an endpoint is unusable"));
    settings.endpoint = QStringLiteral("http://api.example.com/v1/chat/completions");
    check(!settings.endpointProblem().isEmpty() && !settings.isUsable(),
          QStringLiteral("a remote plain-HTTP endpoint is refused"));
    settings.endpoint = QStringLiteral("http://127.0.0.1:8080/v1/chat/completions");
    check(settings.isUsable(),
          QStringLiteral("loopback HTTP is allowed for a local provider"));
    settings.endpoint = QStringLiteral("https://api.example.com/v1/chat/completions");
    check(settings.isUsable(),
          QStringLiteral("an HTTPS endpoint with a model is usable"));
    settings.endpoint = QStringLiteral("ftp://api.example.com/x");
    check(!settings.endpointProblem().isEmpty(),
          QStringLiteral("a non-HTTP endpoint scheme is refused"));
    settings.endpoint = QStringLiteral("https://api.example.com/v1/chat/completions");

    // The local advice the provider must never change.
    Recommendation local;
    local.action = RecommendationAction::Throttle;
    local.category = CatalogCategory::BrowserUpdate;
    local.title = QStringLiteral("Limit background browser updates");
    local.feedbackKey = QStringLiteral("browser-update|id:sha1-4f2a");
    local.suggestedPolicy.scope = QStringLiteral("path");
    local.suggestedPolicy.targetId = QStringLiteral("C:/Apps/updater.exe");
    local.suggestedPolicy.rateBitsPerSecond = 2ULL * 1024ULL * 1024ULL;

    AiContext context;
    context.executableName = QStringLiteral("updater.exe");
    context.categoryToken = QStringLiteral("browser-update");
    context.categoryName = QStringLiteral("Browser update");
    context.destination = QStringLiteral("***.com");
    context.bytesPerSecond = 4ULL * 1024ULL * 1024ULL;
    context.recommendedAction = QStringLiteral("throttle");

    FakeAiProvider provider;
    provider.response.ok = true;
    provider.response.text = QStringLiteral("This is an updater.");

    // Disabled: no request, local advice preserved.
    AiAssistant disabledAssistant;
    disabledAssistant.setSettings(defaults);
    disabledAssistant.setProvider(&provider);
    const AiAssistResult disabled = disabledAssistant.explain(context, local);
    check(disabled.status == AiAssistStatus::Disabled,
          QStringLiteral("a disabled assistant does not ask the provider"));
    checkEqual(provider.calls, 0,
               QStringLiteral("no request is made while AI is off"));
    check(disabled.degraded() && !disabled.usedProvider(),
          QStringLiteral("the disabled result is the local fallback"));
    check(disabled.localRecommendation.action == local.action
              && disabled.localRecommendation.title == local.title
              && disabled.localRecommendation.suggestedPolicy.targetId
                     == local.suggestedPolicy.targetId
              && disabled.localRecommendation.suggestedPolicy.rateBitsPerSecond
                     == local.suggestedPolicy.rateBitsPerSecond,
          QStringLiteral("the local recommendation is returned unchanged"));
    check(!disabled.enforcesAnything(),
          QStringLiteral("an AI result never enforces anything"));
    check(!disabled.explanation.fromProvider,
          QStringLiteral("a disabled result carries no provider explanation"));
    check(disabled.summary().contains(QStringLiteral("local recommendation")),
          QStringLiteral("the disabled result explains the fallback"));

    // Enabled but not configured: still no request.
    AiProviderSettings enabledOnly;
    enabledOnly.enabled = true;
    AiAssistant unconfiguredAssistant;
    unconfiguredAssistant.setSettings(enabledOnly);
    unconfiguredAssistant.setProvider(&provider);
    provider.calls = 0;
    const AiAssistResult unconfigured =
        unconfiguredAssistant.explain(context, local);
    check(unconfigured.status == AiAssistStatus::Unavailable,
          QStringLiteral("an unconfigured provider is unavailable"));
    checkEqual(provider.calls, 0,
               QStringLiteral("an unconfigured provider is never called"));
    check(unconfigured.degraded(),
          QStringLiteral("an unconfigured provider degrades to the local recommendation"));

    // Configured, but no adapter installed.
    AiAssistant noProviderAssistant;
    noProviderAssistant.setSettings(settings);
    const AiAssistResult missing = noProviderAssistant.explain(context, local);
    check(missing.status == AiAssistStatus::Unavailable,
          QStringLiteral("a missing adapter is reported, not guessed"));
    check(missing.detail.contains(QStringLiteral("No AI provider")),
          QStringLiteral("the missing adapter is named"));

    // A successful answer adds explanation text, and nothing else.
    provider.response = AiProviderResponse();
    provider.response.ok = true;
    provider.response.text =
        QStringLiteral("Likely a browser updater.\nIt can be reversed from the policy list.");
    provider.response.model = QStringLiteral("model-x");
    provider.calls = 0;
    AiAssistant assistant;
    assistant.setSettings(settings);
    assistant.setProvider(&provider);
    const AiAssistResult explained = assistant.explain(context, local);
    check(explained.status == AiAssistStatus::Explained
              && explained.usedProvider() && !explained.degraded(),
          QStringLiteral("a successful answer is reported as explained"));
    checkEqual(provider.calls, 1,
               QStringLiteral("the provider is called exactly once"));
    checkEqual(provider.lastPayload, context.toJson(),
               QStringLiteral("the provider receives exactly the bounded context"));
    checkEqual(provider.lastModel, settings.model,
               QStringLiteral("the configured model is used"));
    checkEqual(explained.explanation.model, QStringLiteral("model-x"),
               QStringLiteral("the model that answered is reported"));
    checkEqual(explained.explanation.providerName, QStringLiteral("fake-provider"),
               QStringLiteral("the adapter name is reported"));
    check(explained.explanation.fromProvider
              && explained.explanation.text.contains(QLatin1Char('\n')),
          QStringLiteral("the explanation keeps its line breaks"));
    check(explained.localRecommendation.action == local.action
              && explained.localRecommendation.feedbackKey == local.feedbackKey
              && explained.localRecommendation.suggestedPolicy.targetId
                     == local.suggestedPolicy.targetId,
          QStringLiteral("the provider cannot change the local recommendation"));
    check(explained.summary().contains(QStringLiteral("fake-provider")),
          QStringLiteral("the summary credits the provider"));

    // Provider output that looks like a policy is only text.
    provider.response.text = QStringLiteral("{\"action\":\"block\",\"scope\":\"path\"}");
    const AiAssistResult textual = assistant.explain(context, local);
    checkEqual(textual.localRecommendation.suggestedPolicy.scope, QStringLiteral("path"),
               QStringLiteral("a policy-shaped answer cannot change the scope"));
    check(textual.localRecommendation.action == RecommendationAction::Throttle,
          QStringLiteral("a policy-shaped answer cannot change the action"));
    check(!textual.localRecommendation.suggestedPolicy.description.contains("block"),
          QStringLiteral("a policy-shaped answer is not written into the policy seed"));

    // A failed request degrades to the local recommendation.
    provider.response = AiProviderResponse();
    provider.response.failure = AiFailure::Network;
    const AiAssistResult failed = assistant.explain(context, local);
    check(failed.status == AiAssistStatus::Failed && failed.degraded(),
          QStringLiteral("a provider failure degrades to the local recommendation"));
    check(failed.localRecommendation.suggestedPolicy.targetId
              == local.suggestedPolicy.targetId,
          QStringLiteral("the local policy seed survives a provider failure"));
    check(!failed.detail.isEmpty() && failed.explanation.isEmpty(),
          QStringLiteral("a failure reports why and carries no explanation"));

    // An empty answer is a failure, not a blank explanation.
    provider.response = AiProviderResponse();
    provider.response.ok = true;
    provider.response.text = QStringLiteral("   ");
    const AiAssistResult empty = assistant.explain(context, local);
    check(empty.status == AiAssistStatus::Failed
              && empty.detail.contains(QStringLiteral("empty")),
          QStringLiteral("an empty provider answer degrades to the local advice"));

    // The displayed explanation is sanitised and capped.
    provider.response = AiProviderResponse();
    provider.response.ok = true;
    provider.response.text =
        QStringLiteral("bad\x07 text\n") + QString(5000, QLatin1Char('x'));
    AiProviderSettings capped = settings;
    capped.responseCharacterLimit = 300;
    assistant.setSettings(capped);
    const AiAssistResult bounded = assistant.explain(context, local);
    check(bounded.status == AiAssistStatus::Explained,
          QStringLiteral("an over-long answer is still usable"));
    check(bounded.explanation.text.size() <= 300,
          QStringLiteral("the explanation is capped at the configured length"));
    check(!bounded.explanation.text.contains(QChar(0x07)),
          QStringLiteral("control characters are removed from an explanation"));
    assistant.setSettings(settings);

    // Settings are versioned, clamped, and hold no credential.
    AiProviderSettings persisted;
    persisted.enabled = true;
    persisted.endpoint = QStringLiteral("https://api.example.com/v1/chat/completions");
    persisted.model = QStringLiteral("model-y");
    persisted.timeoutSeconds = 1;
    persisted.responseCharacterLimit = 99999;
    AiProviderSettingsStore settingsStore;
    check(settingsStore.save(persisted),
          QStringLiteral("AI settings save without a store error"));
    const AiProviderSettings reloaded = settingsStore.load();
    check(reloaded.enabled && reloaded.endpoint == persisted.endpoint
              && reloaded.model == QStringLiteral("model-y"),
          QStringLiteral("AI settings round-trip"));
    checkEqual(reloaded.timeoutSeconds, AiProviderSettings::kMinTimeoutSeconds,
               QStringLiteral("the timeout is clamped up to the minimum"));
    checkEqual(reloaded.responseCharacterLimit,
               AiProviderSettings::kMaxResponseCharacters,
               QStringLiteral("the response cap is clamped down to the maximum"));
    {
        AiAssistant fromStore;
        check(fromStore.settings().enabled
                  && fromStore.settings().model == QStringLiteral("model-y"),
              QStringLiteral("a fresh assistant loads the stored settings"));
    }

    const QString settingsJson = AiProviderSettingsStore::toJson(reloaded);
    checkEqual(objectOf(settingsJson).value(QStringLiteral("schemaVersion")).toInt(),
               AiProviderSettingsStore::kSchemaVersion,
               QStringLiteral("the AI settings payload is versioned"));
    check(!settingsJson.toLower().contains(QStringLiteral("key")),
          QStringLiteral("the AI settings payload stores no credential"));

    bool ok = false;
    const AiProviderSettings parsed = AiProviderSettingsStore::fromJson(settingsJson, &ok);
    check(ok && parsed.enabled, QStringLiteral("AI settings parse back"));

    QJsonObject newer = objectOf(settingsJson);
    newer[QStringLiteral("schemaVersion")] =
        AiProviderSettingsStore::kSchemaVersion + 1;
    ok = true;
    const AiProviderSettings rejected = AiProviderSettingsStore::fromJson(
        QString::fromUtf8(QJsonDocument(newer).toJson(QJsonDocument::Compact)), &ok);
    check(!ok && !rejected.enabled,
          QStringLiteral("a newer AI settings schema falls back to disabled"));

    ok = true;
    AiProviderSettingsStore::fromJson(QStringLiteral("not json"), &ok);
    check(!ok, QStringLiteral("malformed AI settings are rejected"));

    // The shipped adapter refuses an unsafe endpoint and a missing key without
    // touching the network.
    OpenAiCompatibleProvider adapter;
    checkEqual(OpenAiCompatibleProvider::apiKeyEnvironmentVariable(),
               QStringLiteral("OASIS_AI_API_KEY"),
               QStringLiteral("the adapter reads its key from a fixed environment variable"));
    check(OpenAiCompatibleProvider::systemPrompt().contains(QStringLiteral("Do not propose"))
              && OpenAiCompatibleProvider::systemPrompt().contains(QStringLiteral("policy")),
          QStringLiteral("the system prompt forbids proposing a policy"));
    check(OpenAiCompatibleProvider::maxResponseBytes() > 0,
          QStringLiteral("the adapter bounds the raw reply size"));

    AiProviderSettings insecure = settings;
    insecure.endpoint = QStringLiteral("http://api.example.com/v1/chat/completions");
    const AiProviderResponse refused =
        adapter.explain(context.boundedJson(), insecure);
    check(!refused.ok && refused.failure == AiFailure::UnsupportedEndpoint,
          QStringLiteral("the shipped adapter refuses a remote plain-HTTP endpoint"));

    qunsetenv("OASIS_AI_API_KEY");
    const AiProviderResponse keyless =
        adapter.explain(context.boundedJson(), settings);
    check(!keyless.ok && keyless.failure == AiFailure::NotConfigured,
          QStringLiteral("the shipped adapter reports a missing key without a request"));

    settingsStore.reset();
    QSettings().clear();
}

// ─── NG-046: AI approval flow ─────────────────────────────────────────────
// AI explains; the policy comes from the deterministic recommendation, and the
// user chooses its scope and duration. Approval writes one ordinary user
// policy; rejection writes nothing.
void testAiApproval()
{
    Recommendation rec;
    rec.action = RecommendationAction::Throttle;
    rec.category = CatalogCategory::BrowserUpdate;
    rec.title = QStringLiteral("Limit background browser updates");
    rec.suggestedPolicy.scope = QStringLiteral("path");
    rec.suggestedPolicy.targetId = QStringLiteral("C:/Apps/updater.exe");
    rec.suggestedPolicy.action = NetworkPolicy::Action::Throttle;
    rec.suggestedPolicy.direction = NetworkDirection::Both;
    rec.suggestedPolicy.rateBitsPerSecond = 2ULL * 1024ULL * 1024ULL * 8ULL;
    rec.suggestedPolicy.source = QStringLiteral("user");
    rec.suggestedPolicy.description = QStringLiteral("Recommended: limit browser updates");

    RecommendationContext context;
    context.observation.executablePath = QStringLiteral("C:/Apps/updater.exe");
    context.observation.publisher = QStringLiteral("Google LLC");
    context.activity = ActivityClassifier().classify(context.observation);

    // The recommendation's own scope first, then the evidence-backed manual
    // targets, without duplicating the path.
    const QList<AiApprovalScopeOption> options =
        aiApprovalScopeOptions(context, rec);
    checkEqual(static_cast<int>(options.size()), 2,
               QStringLiteral("the approved scopes are de-duplicated"));
    check(options.size() == 2 && options.first().scope == QStringLiteral("path"),
          QStringLiteral("the recommendation's scope is offered first"));
    check(options.size() == 2 &&
              options.first().targetId == QStringLiteral("C:/Apps/updater.exe"),
          QStringLiteral("the recommended target is prefilled"));
    check(options.size() == 2 && options.last().scope == QStringLiteral("publisher"),
          QStringLiteral("the observed publisher is an approvable scope"));
    checkEqual(aiApprovalScopeDisplayName(QStringLiteral("group")),
               QStringLiteral("This application group"),
               QStringLiteral("scopes have plain-language names"));

    // A duration is always explicit; the default follows the seed's expiry.
    const QDateTime now = QDateTime::currentDateTimeUtc();
    check(aiApprovalDefaultDuration(rec, now) == AiApprovalDuration::UntilRemoved,
          QStringLiteral("a seed without an expiry defaults to until removed"));
    Recommendation paused = rec;
    paused.suggestedPolicy.action = NetworkPolicy::Action::Block;
    paused.suggestedPolicy.expiration = now.addSecs(3600);
    check(aiApprovalDefaultDuration(paused, now) == AiApprovalDuration::OneHour,
          QStringLiteral("a one-hour seed preselects one hour"));
    check(aiApprovalExpiration(AiApprovalDuration::OneDay, now) == now.addSecs(86400),
          QStringLiteral("a day lasts 24 hours"));
    check(!aiApprovalExpiration(AiApprovalDuration::UntilRemoved, now).isValid(),
          QStringLiteral("until removed has no expiration"));

    // Choices are validated before anything is written.
    AiApprovalChoices choices;
    choices.scope = QStringLiteral("path");
    choices.targetId = QStringLiteral("C:/Apps/updater.exe");
    choices.duration = AiApprovalDuration::OneHour;
    check(aiApprovalProblems(rec, choices, now).isEmpty(),
          QStringLiteral("a scoped, timed choice can be approved"));
    check(!aiApprovalProblems(Recommendation(), choices, now).isEmpty(),
          QStringLiteral("a recommendation without a policy cannot be approved"));
    AiApprovalChoices unscoped;
    unscoped.duration = AiApprovalDuration::OneHour;
    check(!aiApprovalProblems(rec, unscoped, now).isEmpty(),
          QStringLiteral("an approval needs an explicit scope"));
    Recommendation zeroRate = rec;
    zeroRate.suggestedPolicy.rateBitsPerSecond = 0;
    check(!aiApprovalProblems(zeroRate, choices, now).isEmpty(),
          QStringLiteral("a throttle approval needs a rate"));

    // The approved policy is an ordinary user policy: the recommendation
    // decides the action, the user decides scope and duration.
    choices.explanationReviewed = true;
    const NetworkPolicy approved = aiApprovalBuildPolicy(rec, choices, now);
    checkEqual(approved.source, QStringLiteral("user"),
               QStringLiteral("approval creates a normal user policy, never an AI one"));
    check(approved.id.startsWith(QStringLiteral("policy-")),
          QStringLiteral("the approved policy gets its own id"));
    check(approved.action == NetworkPolicy::Action::Throttle,
          QStringLiteral("the local recommendation decides the action"));
    checkEqual(approved.rateBitsPerSecond, rec.suggestedPolicy.rateBitsPerSecond,
               QStringLiteral("the local recommendation decides the rate"));
    checkEqual(approved.scope, QStringLiteral("path"),
               QStringLiteral("the user's scope is stored"));
    checkEqual(approved.targetId, QStringLiteral("C:/Apps/updater.exe"),
               QStringLiteral("the user's target is stored"));
    check(approved.enabled, QStringLiteral("an approved policy is enabled"));
    check(approved.expiration == now.addSecs(3600),
          QStringLiteral("the chosen duration becomes the expiration"));
    check(approved.scheduleType == NetworkPolicy::ScheduleType::Expiration,
          QStringLiteral("a timed policy expires"));
    check(approved.description.contains(QStringLiteral("Approved")) &&
              approved.description.contains(QStringLiteral("AI explanation reviewed")),
          QStringLiteral("the approval note records the review"));

    AiApprovalChoices publisher;
    publisher.scope = QStringLiteral("publisher");
    publisher.targetId = QStringLiteral("Google LLC");
    publisher.duration = AiApprovalDuration::UntilRemoved;
    const NetworkPolicy broad = aiApprovalBuildPolicy(rec, publisher, now);
    checkEqual(broad.scope, QStringLiteral("publisher"),
               QStringLiteral("a broader scope replaces the suggested one"));
    check(!broad.expiration.isValid(),
          QStringLiteral("until removed leaves no expiration"));
    check(broad.scheduleType == NetworkPolicy::ScheduleType::None,
          QStringLiteral("until removed without a window is a plain policy"));

    Recommendation scheduled = rec;
    scheduled.suggestedPolicy.action = NetworkPolicy::Action::Schedule;
    scheduled.suggestedPolicy.schedule = QStringLiteral("overnight");
    scheduled.suggestedPolicy.scheduleType = NetworkPolicy::ScheduleType::Recurring;
    AiApprovalChoices oneDay = publisher;
    oneDay.duration = AiApprovalDuration::OneDay;
    const NetworkPolicy expiringWindow = aiApprovalBuildPolicy(scheduled, oneDay, now);
    check(expiringWindow.scheduleType == NetworkPolicy::ScheduleType::Both,
          QStringLiteral("a timed recurring window keeps both settings"));
    AiApprovalChoices lasting = publisher;
    lasting.duration = AiApprovalDuration::UntilRemoved;
    check(aiApprovalBuildPolicy(scheduled, lasting, now).scheduleType ==
              NetworkPolicy::ScheduleType::Recurring,
          QStringLiteral("an until-removed window stays recurring"));

    // Approval persists exactly one ordinary policy; rejection writes nothing.
    QSettings().clear();
    const int before = PolicyStore::loadPolicies().size();
    check(aiApprovalApprove(approved),
          QStringLiteral("an approved policy is saved"));
    const QList<NetworkPolicy> stored = PolicyStore::loadPolicies();
    checkEqual(static_cast<int>(stored.size()), before + 1,
               QStringLiteral("approval adds exactly one policy"));
    bool found = false;
    for (const NetworkPolicy &policy : stored) {
        if (policy.id != approved.id) continue;
        found = true;
        check(policyOrigin(policy) == PolicyOrigin::User,
              QStringLiteral("the stored policy is a user policy"));
        checkEqual(policy.targetId, approved.targetId,
                   QStringLiteral("the stored policy keeps its target"));
    }
    check(found, QStringLiteral("the approved policy is listed by the store"));

    const QStringList rejectedProblems = aiApprovalProblems(rec, unscoped, now);
    check(!rejectedProblems.isEmpty(),
          QStringLiteral("a rejected choice set is refused before writing"));
    checkEqual(static_cast<int>(PolicyStore::loadPolicies().size()), before + 1,
               QStringLiteral("rejection leaves the stored policy set unchanged"));
    check(!aiApprovalApprove(NetworkPolicy()),
          QStringLiteral("an incomplete policy is never written"));

    QSettings().clear();
}

void runAiTests()
{
    testRecommendationEngine();
    testRecommendationFeedback();
    testAiContext();
    testAiProvider();
    testAiApproval();
}
