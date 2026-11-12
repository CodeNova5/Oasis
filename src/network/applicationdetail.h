/**
 * @file   applicationdetail.h
 * @brief  One assembled view of an application: identity, usage, destinations,
 *         related processes, policy state, and audit history (NG-052).
 * @author Codebuff
 *
 * The detail view is a hub, not a new enforcement path. It answers "what is
 * this, what did it do, what do we know about it, what is controlling it, and
 * what happened before" from evidence the other layers already produce, and it
 * offers the same reversible actions the rest of the product offers (create a
 * policy, review a recommendation, limit or block, verify, open the activity
 * group).
 *
 * Everything in this file is pure: it takes a plain input snapshot and returns
 * display-ready sections. The dialog renders them and the widget performs the
 * actions, so the rules about which policy covers an application, how
 * destinations are ranked, and which action is available are testable without a
 * GUI, a capture thread, or Firewall Manager.
 */

#pragma once

#include <QDateTime>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

#include "attribution/activityclassifier.h"
#include "attribution/dnscorrelator.h"
#include "network/auditeventstore.h"
#include "network/policy.h"

namespace ApplicationDetail {

// Audit history is a sample, not a second audit log: the store keeps the full
// trail and the view shows the most recent entries that reference this app.
constexpr int kMaxAuditEntries = 100;

// ─── Usage ──────────────────────────────────────────────────────────────────
struct Usage
{
    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    quint64 rxBytesPerSecond = 0;
    quint64 txBytesPerSecond = 0;
    quint32 packets = 0;
    // NG-041: advisory session signal, never an observation about the process.
    bool foreground = false;
    bool foregroundHelper = false;
};

// ─── Destination ────────────────────────────────────────────────────────────
// One remote endpoint the application talked to, with the name the attribution
// layers resolved for it. `name` is empty for a direct address: the view says so
// instead of guessing a host.
struct Destination
{
    QString address;
    QString name;
    QString source;            // "DNS answer", "TLS SNI", "DNS and TLS SNI", ...
    QStringList evidence;
    ApplicationIdentity::Confidence confidence = ApplicationIdentity::Confidence::Unknown;
    QDateTime expiresAt;
};

// ─── Related process ────────────────────────────────────────────────────────
// A process the user should see next to this one: a parent, a child, or a
// member of the same activity group. `role` is the reason it is listed.
struct RelatedProcess
{
    QString name;
    quint32 pid = 0;
    QString role;
};

// ─── Policy ─────────────────────────────────────────────────────────────────
struct PolicyEntry
{
    QString id;
    QString summary;           // description when present, else scope + target
    QString scope;
    QString targetId;
    QString action;
    QString direction;
    QString state;             // Active / Inactive / Expired / Disabled / Unsupported
    QString origin;            // user / automatic / unknown
    QDateTime expiration;
    bool inForce = false;
};

// ─── Audit ──────────────────────────────────────────────────────────────────
struct AuditEntry
{
    QDateTime at;
    QString type;
    QString summary;
    QString result;
};

// ─── Action ─────────────────────────────────────────────────────────────────
// `key` is stable so the host can route it: "policy", "recommendation",
// "approval", "internet", "throttle", "verify", "group".
struct ActionState
{
    QString key;
    QString label;
    bool enabled = true;
    QString reason;           // why it is unavailable, empty when enabled
};

// ─── Input ──────────────────────────────────────────────────────────────────
struct Input
{
    QString executableName;
    QString displayName;
    QString executablePath;
    QString identityId;
    QString publisher;
    ApplicationIdentity::SignerStatus signerStatus = ApplicationIdentity::SignerStatus::Unknown;
    quint32 pid = 0;
    qint64 processStartMs = 0;

    QString groupId;
    QString groupName;
    QStringList services;

    ActivityQuery query;
    ActivityClassification activity;
    Usage usage;

    QList<Destination> destinations;
    QList<RelatedProcess> related;
    QList<NetworkPolicy> policies;
    QList<AuditEvent> audit;

    bool internetBlocked = false;
    bool throttleApplied = false;
    QString throttleOwner;     // policy description when a policy owns the limit

    QDateTime now;
};

// ─── Snapshot ───────────────────────────────────────────────────────────────
struct Snapshot
{
    QString title;             // "Google Update (GoogleUpdater.exe)"
    QString subtitle;          // "PID 1234 · foreground application"
    QList<QPair<QString, QString>> facts;    // label, value (identity evidence)
    QString activitySummary;   // "Browser update (Likely)"
    QString activityDetail;    // why, or why nothing matched
    QStringList evidence;
    QString usageText;
    QString foregroundText;
    QList<Destination> destinations;
    QString destinationSummary;
    QList<RelatedProcess> related;
    QString relatedSummary;
    QList<PolicyEntry> policies;
    QString policySummary;
    QList<AuditEntry> audit;
    QString auditSummary;
    QList<ActionState> actions;
};

/// Assembles every section. `input.now` defaults to the current UTC time when
/// invalid, so policy state is never evaluated against an empty timestamp.
Snapshot build(const Input &input);

// ─── Pure rules (also used by the harness) ──────────────────────────────────
/// Exact target match: pid, path/executable, group, service, or publisher. The
/// caller decides whether an enabled or unexpired policy is also in force.
bool policyTargets(const NetworkPolicy &policy, const ActivityQuery &query, quint32 pid);

/// Human summary of a policy: its description, else "scope: target".
QString policySummaryText(const NetworkPolicy &policy);

QString actionLabel(NetworkPolicy::Action action);
QString directionLabel(NetworkDirection direction);
QString signerLabel(ApplicationIdentity::SignerStatus status);
QString originLabel(const QString &source);

/// One line for the audit table: the reason, else the result, else the scope.
QString auditSummaryLine(const AuditEvent &event);

/// Converts one correlator summary into a destination row.
Destination destinationFromSummary(const DestinationNameSummary &summary);

/// De-duplicates by address and name, keeps the strongest confidence, joins the
/// evidence, and ranks named destinations first. Direct addresses stay last.
QList<Destination> mergeDestinations(const QList<Destination> &destinations);

/// Action availability derived from the input: an action that needs a path or a
/// scope is disabled (with a reason) when the evidence does not provide one.
QList<ActionState> buildActions(const Input &input);

QString formatBytes(quint64 bytes);
QString formatRate(quint64 bytesPerSecond);

} // namespace ApplicationDetail
