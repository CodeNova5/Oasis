/**
 * @file    recommendationengine.h
 * @brief   Deterministic local recommendations (NG-042): turns an NG-040
 *          activity classification into a suggested response with its evidence,
 *          confidence, expected effect, and reversal action.
 * @author  Oasis
 *
 * A recommendation is advice only. This engine has no enforcement path, every
 * result requires the user's approval, and the policy it offers is a seed the
 * user may edit or discard — nothing here can apply a policy by itself.
 */
#pragma once

#include <QString>
#include <QStringList>

#include "attribution/activityclassifier.h"
#include "attribution/recommendationfeedback.h"
#include "network/policy.h"

enum class RecommendationAction
{
    Throttle,        // cap the app's rate
    Pause,           // temporary block that restores itself
    Schedule,        // defer the work to a preferred window
    ReviewSettings,  // change nothing; ask the user to look
    NoAction         // nothing to do
};

QString recommendationActionToken(RecommendationAction action);
QString recommendationActionDisplayName(RecommendationAction action);

/**
 * What the engine may consider. `activity` is the NG-040 classification of
 * `observation`; both are passed so the recommendation can state what was seen
 * without re-deriving it.
 */
struct RecommendationContext
{
    ActivityQuery observation;
    ActivityClassification activity;

    bool foreground = false;
    bool meteredConnection = false;
    /// An explicit user policy already covers this app; recommendations must not
    /// second-guess it.
    bool explicitPolicyCovers = false;
    bool exempt = false;

    quint64 bytesPerSecond = 0;
};

struct Recommendation
{
    RecommendationAction action = RecommendationAction::NoAction;
    CatalogCategory category = CatalogCategory::Unknown;
    AttributionConfidenceModel::Assessment assessment;
    QStringList evidence;

    QString title;           // short label, e.g. "Limit background browser updates"
    QString whatObserved;    // what was seen
    QString whyLikely;       // why the activity is likely occurring
    QString expectedEffect;  // what accepting the suggestion would do
    QString reversalAction;  // how to undo it

    /// Always true. Present so a caller cannot treat a recommendation as an
    /// approved decision.
    bool requiresUserApproval = true;
    /// A policy the user may accept after editing. Empty id and target when the
    /// recommendation applies no policy.
    NetworkPolicy suggestedPolicy;

    // NG-043: the local feedback key this recommendation is remembered under,
    // the verdict the user already gave it, and whether that verdict changed
    // the outcome (an incorrect suggestion becomes a review, an unwanted one is
    // hidden).
    QString feedbackKey;
    RecommendationFeedback feedback = RecommendationFeedback::None;
    bool feedbackApplied = false;

    bool hasSuggestedPolicy() const;
    bool enforcesAnything() const { return false; }
    QString confidenceName() const;
    QStringList lines() const;
};

class RecommendationEngine
{
public:
    /// NG-043: local feedback the engine should consult. The store is owned by
    /// the caller and must outlive the engine; without one, feedback is not
    /// applied (useful for tests and for callers that never show suggestions).
    void setFeedbackStore(const RecommendationFeedbackStore *store)
    {
        m_feedback = store;
    }
    const RecommendationFeedbackStore *feedbackStore() const { return m_feedback; }

    /// The stable, local-only key for one activity: category plus the durable
    /// identity (or the best available local identity fallback). No destination
    /// or rate is part of the key.
    static QString feedbackKeyFor(const RecommendationContext &context);

    /// Deterministic category → response mapping. The user's explicit policy,
    /// an exemption, and a foreground session are applied by `recommend()`.
    static RecommendationAction recommendedActionFor(CatalogCategory category);

    /// Rate a throttle suggestion should use: half the observed rate, bounded to
    /// 256 KiB/s–4 MiB/s, or 1 MiB/s when the observed rate is unknown.
    static quint64 suggestedRateBitsPerSecond(quint64 observedBytesPerSecond);

    Recommendation recommend(const RecommendationContext &context) const;

private:
    const RecommendationFeedbackStore *m_feedback = nullptr;
};
