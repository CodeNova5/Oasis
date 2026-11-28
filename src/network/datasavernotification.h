/**
 * @file    datasavernotification.h
 * @brief   Deduplicated, actionable Data Saver notices (DS-011).
 *
 * Every committed throttle, block, or advisory notice becomes one
 * `AppNotification` for the shared `NotificationCoordinator` (NG-051), which
 * owns dedupe, cooldown folding, the rolling delivery cap, and the critical
 * bypass. This module only shapes the notice and routes the two reversal
 * actions; it never shows anything and never applies enforcement.
 *
 * The notice is metadata only. It names the application by base name, includes
 * the attributed domain only when the evidence confidence allows naming it,
 * and carries the milestone, reason, direction/rate, and the real enforcement
 * status. Copy is status-aware: a `requested` throttle is never described as
 * applied, and a failure says the control could not be applied.
 *
 * Actions offered by a notice:
 *  - Allow Once: a tier-2 `SessionOverride` that expires after
 *    `kAllowOnceTtlSeconds` even if the application keeps running;
 *  - Always Allow: a tier-1 `PinnedRule`, created only after explicit
 *    confirmation (the DS-005 gate the store enforces);
 *  - Inspect: the application/evidence details, identified by the decision and
 *    observation ids carried in the message.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QString>
#include <QStringList>

#include "datasaverdecision.h"
#include "datasaverrules.h"
#include "enforcementcoordinator.h"
#include "flowobservation.h"
#include "notificationcoordinator.h"

namespace DataSaverNotifications {
constexpr int kMaxTitleChars = 96;
constexpr int kMaxMessageChars = 600;
constexpr int kMaxReasonChars = 200;
constexpr int kMaxNextStepChars = 160;
/// Allow Once must expire on its own; the user confirms again after this.
constexpr int kAllowOnceTtlSeconds = 60 * 60;

/// Stable action tokens carried by `AppNotification::actions`, so a tray or
/// WebView surface can bind a control without parsing the message.
QString allowOnceActionToken();
QString alwaysAllowActionToken();
QString inspectActionToken();

/// One committed decision plus its enforcement outcome.
struct DecisionNotice
{
    FlowObservation observation;
    PolicyDecision decision;
    EnforcementResult::Status status = EnforcementResult::Status::NotApplied;
    QString enforcementMessage;
    QString enforcementChannels;
    QString enforcementPolicyId;
    /// Base name from the enforcement target; `decision.target.executable` and
    /// then the observation are used when it is empty. A directory path is
    /// reduced to its base name and never recorded.
    QString executableName;
};

/// True for decisions the user should see: throttle, block, or an advisory
/// notice. An allow decision is silent.
bool shouldNotify(const PolicyDecision &decision);

/// Contract §6 mapping:
/// `datasaver:<action>:<executableKey>:<domainKey or flowId>:<milestoneIndex>`.
QString notificationKey(const FlowObservation &observation,
                        const PolicyDecision &decision);

/// A domain may be named only when the evidence confidence is confirmed or
/// strong. Weak inference and unknown stay anonymous.
bool canNameDomain(const PolicyDecision &decision);

/// Builds the notice. Priority is critical for failed enforcement, warning for
/// throttle/block, and info for an advisory notice; the route is TrayAndApp.
AppNotification forDecision(const DecisionNotice &notice);

/// Adds a tier-2 session override that allows the flow (or, when the flow id is
/// unusable, the executable and attributed domain) until it expires. Returns
/// false with `error` when the store rejects the override.
bool allowOnce(const FlowObservation &observation, const PolicyDecision &decision,
               SessionOverrideStore *store, const QDateTime &now = QDateTime(),
               SessionOverride *created = nullptr, QString *error = nullptr);

/// Adds a tier-1 pinned allow rule. `confirmed` must be true; the pinned store
/// refuses the write otherwise. Returns false with `error` when it cannot be
/// stored.
bool alwaysAllow(const FlowObservation &observation, const PolicyDecision &decision,
                 bool confirmed, const QDateTime &now = QDateTime(),
                 PinnedRule *created = nullptr, QString *error = nullptr);
} // namespace DataSaverNotifications
