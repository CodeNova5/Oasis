/**
 * @file    datasaverdecision.h
 * @brief   One validated `PolicyDecision` from fixed precedence (DS-008).
 *
 * The resolver applies the tier order from docs/DATA_SAVER_CONTRACT.md §5:
 *
 *   1 pinned rule -> 2 session override -> 3 profile rule -> 4 cache -> 5 fallback
 *
 * Tier 3 is the DS-006 `LocalSignatureEngine`. Its recommendation is only a
 * candidate: a matching pin or session wins, the signature result supplies the
 * lower-tier conflict vote, and a local guard pass re-checks every automatic
 * candidate before it can become the decision. Profile rules never enforce and
 * this module never applies, withdraws, or stores a policy; DS-009 consumes the
 * decision.
 *
 * The cache tier is a seam for DS-007: the caller supplies an already-built
 * tier-4 decision, and it is accepted only when it validates, targets the same
 * executable/domain as the current observation, and survives the same guards
 * as a profile result. Without that input the resolver falls through to tier 5.
 *
 * `Off` suppresses tiers 3-5. Pinned and session decisions still resolve, so
 * turning automation off never disables a user's own enforcement.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

#include "datasavermode.h"
#include "datasaverprofiles.h"
#include "datasaverrules.h"
#include "flowobservation.h"
#include "network/policy.h"

namespace DataSaverDecision {
constexpr int kSchemaVersion = 1;
constexpr quint64 kGentleThrottleBitsPerSecond = 409600;
} // namespace DataSaverDecision

enum class DecisionOrigin {
    Pinned,
    Session,
    Profile,
    Cache,
    Fallback
};

QString decisionOriginToken(DecisionOrigin origin);
bool decisionOriginFromToken(const QString &text, DecisionOrigin *origin);
int decisionOriginTier(DecisionOrigin origin);

enum class DecisionScope {
    Flow,
    Domain,
    Executable,
    Group
};

QString decisionScopeToken(DecisionScope scope);
bool decisionScopeFromToken(const QString &text, DecisionScope *scope);

enum class ThrottleUntil {
    ForegroundChange,
    MilestoneNext,
    SessionEnd,
    ManualOverride
};

QString throttleUntilToken(ThrottleUntil until);
bool throttleUntilFromToken(const QString &text, ThrottleUntil *until);

struct DecisionTarget
{
    QString executable;
    QString identityId;
    QString domain;
    QString flowId;

    bool isEmpty() const
    {
        return executable.isEmpty() && identityId.isEmpty() && domain.isEmpty()
               && flowId.isEmpty();
    }
};

struct DecisionConflict
{
    bool hasConflict = false;
    int conflictingTier = 0;
    QString resolution = QStringLiteral("applied");
    QString detail;
};

/// Bounded, metadata-only summary. It never carries packet payload, a local
/// address, an executable path, or a provider request body.
struct DecisionEvidence
{
    QString executable;
    QString domain;
    quint64 milestoneBytes = 0;
    int milestoneIndex = 0;
    QString foregroundState;       // foreground_active / foreground_idle / background / unknown
    QString uxProfile;
    QString domainConfidence;      // confirmed / strong_inference / weak_inference / unknown
    bool multiplexed = false;
    bool shared = false;
};

/// The DS-001 §4 decision contract. `validate()` is the local gate: unknown
/// enums, missing required fields, an inconsistent tier/origin, an unsafe
/// automatic block, and invalid rates are rejected rather than normalized.
struct PolicyDecision
{
    static constexpr int kSchemaVersion = DataSaverDecision::kSchemaVersion;

    int schemaVersion = kSchemaVersion;
    QString decisionId;            // dec_ + 8-32 lower-case hex
    QString observationId;         // obs_ + 8-32 lower-case hex
    QDateTime createdAt;
    DecisionOrigin origin = DecisionOrigin::Fallback;
    int tier = 5;
    NetworkPolicy::Action action = NetworkPolicy::Action::Notify;
    bool continueAfterNotify = true;
    DecisionScope scope = DecisionScope::Executable;
    DecisionTarget target;
    NetworkDirection direction = NetworkDirection::Download;
    quint64 rateBitsPerSecond = 0; // throttle only
    ThrottleUntil until = ThrottleUntil::MilestoneNext;
    double confidence = 0.0;
    SignatureClassification classification = SignatureClassification::Unknown;
    DecisionConflict conflict;
    DecisionEvidence evidence;
    QString reasonShort;
    QStringList nextSteps;

    QJsonObject toJson() const;

    /// A missing `schemaVersion` is read as 1, a newer one is rejected whole,
    /// and every parsed field is validated before `decision` is written.
    static bool fromJson(const QJsonObject &object, PolicyDecision *decision,
                         QString *error = nullptr);

    bool validate(QString *error = nullptr) const;

    bool isAutomatic() const
    {
        return origin == DecisionOrigin::Profile || origin == DecisionOrigin::Cache
               || origin == DecisionOrigin::Fallback;
    }
};

struct ResolverInput
{
    /// The DS-003 observation plus the identity/attribution evidence the caller
    /// already resolved. `signature.observation` is the authoritative observation.
    LocalSignatureInput signature;
    DataSaverMode::Mode mode = DataSaverMode::Mode::Off;
    QList<PinnedRule> pinnedRules;
    QList<SessionOverride> sessionOverrides;

    /// Optional tier-4 candidate from DS-007. Ignored unless it is a valid
    /// cache-origin decision for this executable and domain.
    const PolicyDecision *cachedDecision = nullptr;

    /// The caller confirmed that an enforcement channel can own a gentle
    /// throttle. Without it the fallback stays notify-only.
    bool gentleThrottleAvailable = false;

    /// Invalid means "use the current UTC time". Tests supply a fixed value.
    QDateTime now;
};

struct DecisionResolution
{
    bool evaluated = false;            // a decision was produced
    bool automationSuppressed = false; // Off withheld tiers 3-5
    PolicyDecision decision;
    QString diagnostic;
};

class DecisionResolver
{
public:
    DecisionResolver();
    explicit DecisionResolver(LocalSignatureEngine engine);

    DecisionResolution resolve(const ResolverInput &input) const;

    const LocalSignatureEngine &signatureEngine() const { return m_engine; }
    bool setProfileRules(const QList<ProfileRule> &rules, QString *error = nullptr);

private:
    LocalSignatureEngine m_engine;
};
