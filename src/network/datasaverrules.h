/**
 * @file    datasaverrules.h
 * @brief   Durable user-pinned rules and bounded session overrides (DS-005).
 *
 * Pins are tier 1 (docs/DATA_SAVER_CONTRACT.md §5): they match an executable
 * plus an exact domain or wildcard, are always origin `user`, survive Off and
 * Emergency Restore, and are never mutated by a lower-tier disagreement.
 * Session overrides are tier 2 and live only in memory; a new store (a process
 * restart) starts empty, and an optional absolute expiry bounds one further.
 *
 * Persistence reuses the existing `PolicyStore` conventions: a QSettings group
 * with an integer schema version and one JSON array. A newer schema is rejected
 * whole, individual malformed rules are skipped with a diagnostic, and a write
 * that would overwrite a newer store is refused.
 *
 * This module stores and resolves; it never applies, withdraws, or bypasses an
 * enforcement channel. DS-008 consumes the resolution and DS-009 applies a
 * winning enforcement-owned outcome.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QJsonObject>
#include <QList>
#include <QString>

#include "flowobservation.h"
#include "network/policy.h"

namespace DataSaverRules {
constexpr int kSchemaVersion = 1;
constexpr quint64 kDefaultThrottleBitsPerSecond = 409600;
} // namespace DataSaverRules

struct PinnedRule
{
    QString id;                          // pin_ + 8–32 lower-case hex
    QString executable;                  // normalized base name, e.g. code.exe
    QString domainPattern;               // example.com, *.example.com, or *
    NetworkPolicy::Action action = NetworkPolicy::Action::Allow;
    bool continueAfterNotify = false;    // true for notify_then_continue
    NetworkDirection direction = NetworkDirection::Both;
    quint64 rateBitsPerSecond = 0;       // required when action is Throttle
    QDateTime createdAt;
    QDateTime expiresAt;                 // invalid = persistent
    QString description;

    bool isActiveAt(const QDateTime &now) const;
};

enum class SessionScope {
    Flow,
    ExecutableDomain
};

QString sessionScopeToken(SessionScope scope);
bool sessionScopeFromToken(const QString &text, SessionScope *scope);

struct SessionOverride
{
    QString id;                          // ses_ + 8–32 lower-case hex
    SessionScope scope = SessionScope::ExecutableDomain;
    QString flowId;                      // required for Flow scope
    QString executable;                  // required for ExecutableDomain scope
    QString domainPattern;               // required for ExecutableDomain scope
    NetworkPolicy::Action action = NetworkPolicy::Action::Allow;
    bool continueAfterNotify = false;
    NetworkDirection direction = NetworkDirection::Both;
    quint64 rateBitsPerSecond = 0;
    QDateTime createdAt;
    QDateTime expiresAt;                 // invalid = until session end

    bool isActiveAt(const QDateTime &now) const;
};

struct PinnedRuleLoadResult
{
    QList<PinnedRule> rules;
    QString diagnostic;                  // empty on a clean read
    bool rejectedNewer = false;
    int skipped = 0;
};

class PinnedRuleStore
{
public:
    static QString storageGroup() { return QStringLiteral("Oasis/DataSaver/PinnedRules"); }

    static PinnedRuleLoadResult load();

    /// Writes the whole set. Refuses when any rule is invalid or when the stored
    /// schema is newer than this build.
    static bool save(const QList<PinnedRule> &rules, QString *error = nullptr);

    /// Adds one rule. An `Allow` rule requires `alwaysAllowConfirmed == true`;
    /// this is the "Always Allow" gate from the ticket. Fills `rule.id` when it
    /// is empty. Other actions persist without a second confirmation.
    static bool add(PinnedRule &rule, bool alwaysAllowConfirmed, QString *error = nullptr);

    static bool remove(const QString &id, QString *error = nullptr);

    /// Serialization used by the store and its tests.
    static QJsonObject toJson(const PinnedRule &rule);
    static bool fromJson(const QJsonObject &object, PinnedRule *rule, QString *error = nullptr);

private:
    static bool validate(PinnedRule *rule, QString *error);
    static bool loadForWrite(QList<PinnedRule> *rules, QString *error);
};

class SessionOverrideStore
{
public:
    /// A default-constructed store is the restart boundary: no session overrides.
    SessionOverrideStore() = default;

    bool add(SessionOverride &override, QString *error = nullptr);
    bool remove(const QString &id);
    QList<SessionOverride> all() const { return m_overrides; }
    QList<SessionOverride> activeOverrides(const QDateTime &now) const;
    int count() const { return static_cast<int>(m_overrides.size()); }
    void clear() { m_overrides.clear(); }

private:
    QList<SessionOverride> m_overrides;
};

/// A lower-tier (profile/cache/fallback) opinion supplied by the caller. It is
/// only used to report a conflict; the resolver never edits a pinned rule.
struct LowerTierVote
{
    int tier = 3;
    NetworkPolicy::Action action = NetworkPolicy::Action::NoAction;
    bool continueAfterNotify = false;
    QString source;
    QString ruleId;
};

struct RuleMatch
{
    bool matched = false;
    int tier = 0;                        // 1 pinned, 2 session
    QString ruleId;
    QString origin;                      // "pinned" or "session"
    NetworkPolicy::Action action = NetworkPolicy::Action::NoAction;
    bool continueAfterNotify = false;
    NetworkDirection direction = NetworkDirection::Both;
    quint64 rateBitsPerSecond = 0;
    QString scope;                       // "executable" or "flow"
    QString executable;
    QString domain;
    QString flowId;
};

struct ConflictReport
{
    bool hasConflict = false;
    int conflictingTier = 0;
    QString conflictingRuleId;
    QString resolution = QStringLiteral("applied");
    QString detail;
};

struct RuleResolution
{
    bool matched = false;
    RuleMatch winner;
    ConflictReport conflict;
};

class RuleResolver
{
public:
    /// Resolves the highest-precedence rule for one observation. Pins beat
    /// sessions; a matching lower tier that disagrees is reported in `conflict`
    /// while the winner and every stored rule stay unchanged.
    static RuleResolution resolve(const FlowObservation &observation,
                                  const QList<PinnedRule> &pins,
                                  const QList<SessionOverride> &sessions,
                                  const QDateTime &now,
                                  const QList<LowerTierVote> &lowerTiers = QList<LowerTierVote>());

    /// Exposed for matching tests and for later policy application.
    static bool executableMatches(const QString &ruleExecutable, const QString &exeName);
    static bool domainPatternMatches(const QString &pattern, const QString &domain);
    static QString normalizeExecutable(const QString &name);
    static QString normalizeDomainPattern(const QString &pattern);
};
