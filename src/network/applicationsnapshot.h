/**
 * @file    applicationsnapshot.h
 * @brief   Screen 03 — Applications (SCREENS_SPEC.md): one display-ready row
 *          per process, assembled from evidence the capture and identity layers
 *          already produce.
 *
 * The snapshot is deliberately plain: no widget, no policy, no enforcement
 * path. NetworkWidget fills it once per one-second beat, and the Applications
 * page renders it. Classification helpers are pure so the vocabulary of the
 * screen (Foreground / Background / System) is decided in one place.
 *
 * @author  Oasis
 */
#pragma once

#include <QIcon>
#include <QString>
#include <QStringList>

namespace Applications {

struct Snapshot
{
    quint32 pid = 0;
    QIcon icon;                // the executable's own icon, empty until resolved
    QString name;              // executable, e.g. "chrome.exe"
    QString displayName;       // friendly identity, empty when unresolved
    QString path;              // executable path, empty when unresolved
    QString publisher;         // verified signer, empty when unknown
    QStringList services;      // Windows services hosted by this process

    // Display vocabulary from SCREENS_SPEC.md §Screen 03.
    QString activity;          // "Foreground", "Background" or "System"
    QString policy;            // "None", "Throttle (Active)", "Block (Active)"
    QString policyToken;       // "none", "restricted" or "blocked"
    QString identity;          // "Confirmed", "Likely", "Possible", "Unknown"

    quint64 rxBytesPerSecond = 0;
    quint64 txBytesPerSecond = 0;
    quint64 totalBytes = 0;

    bool isActive() const { return rxBytesPerSecond + txBytesPerSecond > 0; }
    quint64 bytesPerSecond() const { return rxBytesPerSecond + txBytesPerSecond; }
    QString label() const
    {
        return displayName.trimmed().isEmpty() ? name : displayName;
    }
};

/// A process that hosts Windows services is presented as a system service,
/// even when a foreground association exists. Otherwise the observed foreground
/// association wins, and everything else is background activity.
inline QString activityState(bool hostsServices, bool foreground)
{
    if (hostsServices)
        return QStringLiteral("System");
    if (foreground)
        return QStringLiteral("Foreground");
    return QStringLiteral("Background");
}

/// Only a state the shell can actually observe is named here. A stored-only
/// policy is not live enforcement, so it is never reported as active.
inline QString policyLabel(bool blocked, bool throttled)
{
    if (blocked)
        return QStringLiteral("Block (Active)");
    if (throttled)
        return QStringLiteral("Throttle (Active)");
    return QStringLiteral("None");
}

inline QString policyTokenFor(bool blocked, bool throttled)
{
    if (blocked)
        return QStringLiteral("blocked");
    if (throttled)
        return QStringLiteral("restricted");
    return QStringLiteral("none");
}

} // namespace Applications
