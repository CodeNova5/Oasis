/**
 * @file    aiapproval.h
 * @brief   AI approval flow (NG-046): the explicit scope and duration behind an
 *          approved policy, and the policy that approval creates.
 * @author  Oasis
 *
 * AI explains; it never proposes the policy. The action, rate, and schedule of
 * an approved policy come from the NG-042 recommendation, which is
 * deterministic, and the user chooses the scope and duration before approving.
 *
 * Approval creates an ordinary policy with `source` = "user": it is stored in
 * the same `PolicyStore` as one the editor created, listed by the Policies
 * dialog, and preserved by emergency restore. Rejection calls nothing here, so
 * a rejected suggestion cannot change stored policies or enforcement state.
 *
 * The helpers in this file are widget-free so the choice, validation, and
 * build rules can be checked without a GUI.
 */
#pragma once

#include <QDateTime>
#include <QList>
#include <QString>
#include <QStringList>

#include "attribution/recommendationengine.h"
#include "network/policy.h"

// ─── Duration ──────────────────────────────────────────────────────────────
// Every approval names a duration. "Until removed" is an explicit choice, not
// an omission: it produces a policy with no expiration that stays listed until
// the user removes it.
enum class AiApprovalDuration {
    OneHour,
    OneDay,
    OneWeek,
    UntilRemoved
};

QString aiApprovalDurationToken(AiApprovalDuration duration);
QString aiApprovalDurationDisplayName(AiApprovalDuration duration);
/// Seconds the duration lasts; 0 for UntilRemoved.
qint64 aiApprovalDurationSeconds(AiApprovalDuration duration);
/// UTC expiration for the duration, or an invalid QDateTime for UntilRemoved.
QDateTime aiApprovalExpiration(AiApprovalDuration duration, const QDateTime &nowUtc);

/// All durations, narrowest first, for a combo box.
QList<AiApprovalDuration> aiApprovalDurations();

// ─── Scope ─────────────────────────────────────────────────────────────────
/// One scope the user may approve. Only scopes backed by evidence for the
/// observed activity are offered, so an approval cannot invent a publisher or
/// service the application never saw.
struct AiApprovalScopeOption
{
    QString scope;      // policy scope token: "path", "group", "service", "publisher"
    QString targetId;
    QString label;
};

QString aiApprovalScopeDisplayName(const QString &scope);

/// The recommendation's own seed first, then the activity's manual targets,
/// de-duplicated by scope and target.
QList<AiApprovalScopeOption> aiApprovalScopeOptions(const RecommendationContext &context,
                                                    const Recommendation &recommendation);

/// Best duration to preselect for a recommendation: the nearest option to the
/// seed's expiration, or UntilRemoved when the seed does not expire.
AiApprovalDuration aiApprovalDefaultDuration(const Recommendation &recommendation,
                                             const QDateTime &nowUtc);

// ─── Choice and approval ───────────────────────────────────────────────────
struct AiApprovalChoices
{
    QString scope;
    QString targetId;
    AiApprovalDuration duration = AiApprovalDuration::UntilRemoved;
    /// True when the user asked the provider for an explanation before
    /// approving. It only changes the approval note; it cannot change the
    /// policy's action, scope, rate, or schedule.
    bool explanationReviewed = false;
};

/// Empty when the choices can be approved. Each problem is a sentence shown to
/// the user before anything is written.
QStringList aiApprovalProblems(const Recommendation &recommendation,
                               const AiApprovalChoices &choices,
                               const QDateTime &nowUtc);

/**
 * Build the ordinary policy an approval creates.
 *
 * The action, rate, direction, and any recurring window are copied from the
 * recommendation's suggested policy; scope, target, and duration come from the
 * user's choices. The id is newly generated, `source` is "user" (never "AI"),
 * and the description records that the policy came from an approved
 * recommendation, so it is listed and preserved like any other user policy.
 */
NetworkPolicy aiApprovalBuildPolicy(const Recommendation &recommendation,
                                    const AiApprovalChoices &choices,
                                    const QDateTime &nowUtc);

/// Append (or replace by id) an approved policy in `PolicyStore`. The only
/// function in this flow that writes anything.
bool aiApprovalApprove(const NetworkPolicy &policy);
