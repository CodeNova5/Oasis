/**
 * @file   enforcementrestore.h
 * @brief  Enforcement channel routing and emergency-restore planning (NG-026).
 *
 * Two decisions live here so they can be tested without COM, elevation, a
 * worker thread, or WinDivert:
 *
 *  - which enforcement channel a policy needs (firewall, QoS upload, WinDivert
 *    download), so the coordinator does not guess;
 *  - which policies emergency restore may take back. Only policies the product
 *    created for itself are removed; anything the user created survives, and a
 *    policy whose origin cannot be established is preserved rather than
 *    deleted.
 *
 * @author Codebuff
 */

#pragma once

#include <QList>
#include <QMetaType>
#include <QString>
#include <QStringList>

#include "network/policy.h"

// ─── Enforcement channels ───────────────────────────────────────────────────
// A throttle needs both shaping channels at once (QoS for upload, the WinDivert
// shaper for download), so these are independent flags rather than one enum.
struct PolicyChannels
{
    bool firewall = false;
    bool throttle = false;
    bool uploadShaping = false;
    bool downloadShaping = false;

    bool any() const { return firewall || throttle; }
    bool operator==(const PolicyChannels &other) const
    {
        return firewall == other.firewall && throttle == other.throttle &&
               uploadShaping == other.uploadShaping &&
               downloadShaping == other.downloadShaping;
    }
};

// What the coordinator must do to enforce this policy. Disabled policies, and
// actions such as Notify or Ask that are advisory, need no channel at all.
PolicyChannels plannedChannels(const NetworkPolicy &policy);

// Human-readable channel list: "firewall", "QoS upload + WinDivert download",
// or "none".
QString channelsDescription(const PolicyChannels &channels);

// ─── Emergency restore ──────────────────────────────────────────────────────
struct EmergencyRestoreEntry
{
    QString policyId;
    QString target;
    QString channel;   // "policy store" or "throttle"
    QString outcome;   // "removed", "preserved", "failed", "requested", "skipped"
    QString message;
};

struct EmergencyRestorePlan
{
    QList<NetworkPolicy> automatic;  // the product's own controls, removed
    QList<NetworkPolicy> preserved;  // user-created or unknown origin, kept
};

EmergencyRestorePlan buildEmergencyRestorePlan(const QList<NetworkPolicy> &policies);

struct EmergencyRestoreReport
{
    int removed = 0;
    int preserved = 0;
    int failed = 0;
    QStringList removedIds;
    QStringList preservedIds;
    QList<EmergencyRestoreEntry> entries;
    bool throttleRestoreRequested = false;
    QString throttleMessage;

    bool ok() const { return failed == 0; }
    // One line for the status bar.
    QString summary() const;
    // One line per action for the user-facing dialog.
    QStringList lines() const;
};

// Turns a plan into a report. Kept separate from the coordinator so the shape
// of the report is testable: the caller supplies whether the throttle channel
// accepted the request and what it said about it.
EmergencyRestoreReport applyEmergencyRestorePlan(const EmergencyRestorePlan &plan,
                                                 bool throttleRestoreRequested,
                                                 const QString &throttleMessage,
                                                 bool storeWriteSucceeded = true);

Q_DECLARE_METATYPE(EmergencyRestoreReport)
