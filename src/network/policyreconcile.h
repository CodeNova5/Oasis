/**
 * @file   policyreconcile.h
 * @brief  Verify stored policies against what Windows is enforcing (NG-024).
 *
 * A policy is only meaningful if the firewall rule or shaping limit it asked
 * for still exists, and if the controls that exist still belong to a policy.
 * This module compares the stored, currently active policies with what the
 * enforcement channels report, then repairs what is missing and removes what
 * this product's policies left behind.
 *
 * Attribution matters more than completeness here. Firewall rules created by
 * a policy carry its id in the rule description; rules created from the
 * Firewall tab do not. Only attributed rules are ever removed, and only
 * automatically applied bandwidth limits are taken back. Anything that cannot
 * be attributed is reported as left in place instead of guessed at.
 *
 * @author Codebuff
 */

#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QMetaType>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>

#include "network/policy.h"

class FirewallManager;
class ThrottlePolicyManager;

// ─── What Windows currently enforces ────────────────────────────────────────
struct FirewallObservation
{
    QString name;
    QString path;
    bool block = false;
    bool inbound = false;
    bool enabled = true;
    QString policyId;      // empty when the rule was not created by a policy
};

struct PolicyObservation
{
    QList<FirewallObservation> firewallRules;  // NetGuard rules only
    QSet<QString> throttledPaths;              // normalized
    QSet<QString> autoAppliedPaths;            // subset the product may remove
    QHash<QString, QString> throttlePolicyIds; // normalized path -> policy id
    QHash<QString, quint64> downloadLimits;    // normalized path -> bits/s
};

// ─── What to do about it ────────────────────────────────────────────────────
struct ReconciliationAction
{
    enum class Kind { CreateFirewallRule, RemoveFirewallRule, ApplyThrottle,
                      ReassignThrottle, RemoveThrottle, Report };

    Kind kind = Kind::Report;
    QString policyId;
    QString path;          // original form, for the manager call
    QString ruleName;      // RemoveFirewallRule only
    bool block = false;    // CreateFirewallRule only
    bool automatic = false; // ApplyThrottle only
    QString message;
};

struct ReconciliationReport
{
    QList<ReconciliationAction> actions;
    int repaired = 0;
    int removed = 0;
    int failed = 0;
    int unattributed = 0;   // reported and deliberately left in place
    int unresolved = 0;     // scope or conflict could not be resolved

    bool ok() const { return failed == 0; }
    QString summary() const;
    QStringList lines() const;
};

Q_DECLARE_METATYPE(ReconciliationReport)

// "NetGuard policy <id>" -> "<id>"; anything else -> empty.
QString reconciledPolicyId(const QString &ruleDescription);

// Pure plan: compares active policies (with the running paths of any groups
// they target) with the observed state. Performs no I/O and calls no manager.
ReconciliationReport planPolicyReconciliation(
    const QList<NetworkPolicy> &policies,
    const QHash<QString, QStringList> &groupPaths,
    const PolicyObservation &observed,
    const QDateTime &now);

// ─── Executor ───────────────────────────────────────────────────────────────
class PolicyReconciler : public QObject
{
    Q_OBJECT
public:
    PolicyReconciler(ThrottlePolicyManager *throttle, FirewallManager *firewall,
                     QObject *parent = nullptr);

    // Reads the stored policies and both enforcement channels, then applies the
    // plan. `groupPaths` is the running executables per activity group, which
    // is what a group-scoped policy is checked against.
    ReconciliationReport reconcileNow(const QHash<QString, QStringList> &groupPaths);

signals:
    void reconciliationFinished(const ReconciliationReport &report);

private:
    ThrottlePolicyManager *m_throttle = nullptr;
    FirewallManager *m_firewall = nullptr;
};
